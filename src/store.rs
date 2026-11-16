use crate::{
    crypto::{self, Crypto},
    upstream::{GistRef, Upstream},
};
use anyhow::{Context, Result};
use serde::Serialize;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    FromRow, SqlitePool,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub const CACHE_LIMIT: usize = 4 * 1024 * 1024;
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub struct SourceHealth {
    version: i64,
    at: i64,
    success: bool,
}

#[derive(Clone)]
pub struct App {
    pub db: SqlitePool,
    pub crypto: Crypto,
    pub upstream: Upstream,
    pub dev: bool,
    pub login_gate: Arc<tokio::sync::Semaphore>,
    pub attempts: Arc<Mutex<HashMap<String, Vec<i64>>>>,
    pub trust_proxy: bool,
    pub stats: Arc<Mutex<HashMap<i64, (i64, i64)>>>,
    pub deliveries: Arc<tokio::sync::Semaphore>,
    pub health: Arc<Mutex<HashMap<i64, SourceHealth>>>,
}
#[derive(Serialize, FromRow, Clone)]
pub struct Source {
    pub id: i64,
    pub name: String,
    pub owner: String,
    pub gist_id: String,
    pub filename: String,
    pub version: i64,
    pub last_ok: Option<i64>,
    pub last_error: Option<String>,
    #[sqlx(default)]
    pub share_count: i64,
}
impl Source {
    pub fn gist(&self) -> GistRef {
        GistRef {
            owner: self.owner.clone(),
            gist_id: self.gist_id.clone(),
            filename: self.filename.clone(),
        }
    }
}
#[derive(Serialize, FromRow, Clone)]
pub struct Share {
    pub id: i64,
    pub source_id: i64,
    pub label: String,
    pub slug: String,
    pub filename: String,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub last_access: Option<i64>,
    pub access_count: i64,
    pub source_name: String,
    #[sqlx(default)]
    pub last_fetch: Option<i64>,
    #[sqlx(default)]
    pub last_ip: Option<String>,
}
#[derive(Serialize, FromRow, Clone)]
pub struct ShareFetch {
    pub fetched_at: i64,
    pub ip: Option<String>,
}
#[derive(Serialize, FromRow, Clone)]
pub struct Settings {
    pub base_url: String,
    pub cache_ttl_secs: i64,
}
#[derive(FromRow)]
pub struct Session {
    pub csrf: String,
}
#[derive(FromRow, Clone)]
pub struct Grant {
    pub source_id: i64,
    pub token_hash: Vec<u8>,
    pub enabled: bool,
    pub expires_at: Option<i64>,
    pub filename: String,
    pub id: i64,
}
impl Grant {
    pub fn accepts(&self, token: &str, filename: &str) -> bool {
        self.enabled
            && self.filename == filename
            && self.expires_at.is_none_or(|t| t > now())
            && crypto::matches(token, &self.token_hash)
    }
}

pub async fn database(dir: &Path) -> Result<SqlitePool> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let options = SqliteConnectOptions::new()
        .filename(dir.join("gateway.sqlite"))
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(3))
        .pragma("cache_size", "-512")
        .pragma("mmap_size", "0");
    let pool = SqlitePoolOptions::new()
        .max_connections(2)
        .min_connections(1)
        .connect_with(options)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            dir.join("gateway.sqlite"),
            std::fs::Permissions::from_mode(0o600),
        )?;
    }
    Ok(pool)
}
pub fn write_key(dir: &Path) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(dir.join("master.key"))
        .context("密钥文件已存在或无法创建；不会覆盖")?;
    file.write_all(&crypto::random_bytes::<32>())?;
    file.sync_all()?;
    Ok(())
}
impl App {
    pub async fn load(dir: &Path, dev: bool) -> Result<Self> {
        let key = std::fs::read(dir.join("master.key")).context("找不到密钥，请先执行 init")?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| anyhow::anyhow!("密钥长度错误"))?;
        let db = database(dir).await?;
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM admins")
            .fetch_one(&db)
            .await?;
        anyhow::ensure!(count == 1, "请先执行 init 建立管理员");
        Ok(Self {
            db,
            crypto: Crypto::new(key),
            upstream: Upstream::new(2 * 1024 * 1024, CACHE_LIMIT, 2)?,
            dev,
            login_gate: Arc::new(tokio::sync::Semaphore::new(1)),
            attempts: Arc::new(Mutex::new(HashMap::new())),
            trust_proxy: false,
            stats: Arc::new(Mutex::new(HashMap::new())),
            deliveries: Arc::new(tokio::sync::Semaphore::new(8)),
            health: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub async fn settings(&self) -> Result<Settings, sqlx::Error> {
        sqlx::query_as("SELECT base_url,cache_ttl_secs FROM settings WHERE id=1")
            .fetch_one(&self.db)
            .await
    }
    pub async fn source(&self, id: i64) -> Result<Option<Source>, sqlx::Error> {
        sqlx::query_as("SELECT *,0 AS share_count FROM sources WHERE id=?")
            .bind(id)
            .fetch_optional(&self.db)
            .await
    }
    pub async fn session(&self, token: &str) -> Result<Option<Session>, sqlx::Error> {
        sqlx::query_as("SELECT csrf FROM sessions WHERE token_hash=? AND expires_at>?")
            .bind(crypto::digest(token))
            .bind(now())
            .fetch_optional(&self.db)
            .await
    }
    pub async fn link(&self, id: i64) -> Result<Option<String>> {
        let row: Option<(String, String, String)> =
            sqlx::query_as("SELECT slug,filename,token_ciphertext FROM shares WHERE id=?")
                .bind(id)
                .fetch_optional(&self.db)
                .await?;
        let Some((slug, filename, encrypted)) = row else {
            return Ok(None);
        };
        let token = self.crypto.open(&encrypted)?;
        let base = self.settings().await?.base_url;
        Ok(Some(format!("{base}/s/{slug}/{token}/{filename}")))
    }
    pub async fn record(&self, id: i64) {
        let mut stats = self.stats.lock().await;
        if stats.len() >= 2048 && !stats.contains_key(&id) {
            return;
        }
        let entry = stats.entry(id).or_insert((0, 0));
        entry.0 += 1;
        entry.1 = now();
    }
    pub async fn record_fetch(&self, id: i64, ip: Option<&str>) {
        let Ok(mut tx) = self.db.begin().await else {
            return;
        };
        let at = now();
        if sqlx::query("INSERT INTO share_fetches(share_id,fetched_at,ip) VALUES(?,?,?)")
            .bind(id)
            .bind(at)
            .bind(ip)
            .execute(&mut *tx)
            .await
            .is_err()
        {
            return;
        }
        let _ = sqlx::query(
            "DELETE FROM share_fetches WHERE share_id=? AND id < (SELECT id FROM share_fetches WHERE share_id=? ORDER BY id DESC LIMIT 1 OFFSET 29)",
        )
        .bind(id)
        .bind(id)
        .execute(&mut *tx)
        .await;
        let _ = tx.commit().await;
    }
    pub async fn record_health(&self, id: i64, version: i64, success: bool) {
        let mut health = self.health.lock().await;
        if health.len() < 512 || health.contains_key(&id) {
            health.insert(
                id,
                SourceHealth {
                    version,
                    at: now(),
                    success,
                },
            );
        }
    }
    pub async fn flush_stats(&self) {
        let health = std::mem::take(&mut *self.health.lock().await);
        for (
            id,
            SourceHealth {
                version,
                at,
                success,
            },
        ) in health
        {
            let _ = if success {
                sqlx::query("UPDATE sources SET last_ok=?,last_error=NULL WHERE id=? AND version=?")
                    .bind(at)
                    .bind(id)
                    .bind(version)
                    .execute(&self.db)
                    .await
            } else {
                sqlx::query("UPDATE sources SET last_error='读取失败，请检查 Gist、网络或大小限制' WHERE id=? AND version=?")
                    .bind(id).bind(version).execute(&self.db).await
            };
        }
        let pending = std::mem::take(&mut *self.stats.lock().await);
        if !pending.is_empty() {
            if let Ok(mut tx) = self.db.begin().await {
                for (id, (count, time)) in pending {
                    let _=sqlx::query("UPDATE shares SET access_count=access_count+?,last_access=MAX(COALESCE(last_access,0),?) WHERE id=?").bind(count).bind(time).bind(id).execute(&mut *tx).await;
                }
                let _ = tx.commit().await;
            }
        }
        let _ = sqlx::query("DELETE FROM sessions WHERE expires_at<=?")
            .bind(now())
            .execute(&self.db)
            .await;
    }
}
