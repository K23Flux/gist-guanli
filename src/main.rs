mod config;
mod crypto;
mod store;
mod upstream;
mod web;

use anyhow::{bail, Context, Result};
use clap::Parser;
use config::{Cli, Command};
use std::io::{self, Read};

fn main() -> Result<()> {
    let cli = Cli::parse();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?
        .block_on(run(cli))
}
async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init {
            secret_stdin,
            public_url,
            dev,
        } => {
            let base = config::normalize_base(&public_url, dev)?;
            if cli.data_dir.join("master.key").exists()
                || cli.data_dir.join("gateway.sqlite").exists()
            {
                bail!("数据目录已初始化或存在文件，不会覆盖；请保留并备份原数据");
            }
            let secret = if secret_stdin {
                let mut s = String::new();
                io::stdin().take(4097).read_to_string(&mut s)?;
                s.trim_end_matches(['\r', '\n']).to_owned()
            } else {
                let a = rpassword::prompt_password("设置管理员口令（至少 12 个字符）：")?;
                let b = rpassword::prompt_password("再次输入：")?;
                if a != b {
                    bail!("两次输入不一致");
                }
                a
            };
            if secret.chars().count() < 12 || secret.len() > 1024 {
                bail!("口令需要至少 12 个字符，最多 1024 字节");
            }
            let hashed = crypto::hash_secret(&secret)?;
            let db = store::database(&cli.data_dir).await?;
            store::write_key(&cli.data_dir)?;
            let mut tx = db.begin().await?;
            sqlx::query("INSERT INTO admins(id,pass_hash) VALUES(1,?)")
                .bind(hashed)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO settings(id,base_url,cache_ttl_secs) VALUES(1,?,60)")
                .bind(base)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            db.close().await;
            println!("初始化完成。请分别备份数据库与 master.key；未启动任何监听。");
        }
        Command::Serve { bind, dev } => {
            if dev && !bind.ip().is_loopback() {
                bail!("开发模式只能绑定本机回环地址");
            }
            let app = store::App::load(&cli.data_dir, dev).await?;
            config::normalize_base(&app.settings().await?.base_url, dev)?;
            let router = web::router(app.clone());
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .context("无法绑定服务端口")?;
            eprintln!("Gist Gateway 已启动：{bind}；日志不会记录请求地址或订阅令牌。");
            let stats_app = app.clone();
            let worker = tokio::spawn(async move {
                let mut timer = tokio::time::interval(std::time::Duration::from_secs(30));
                loop {
                    timer.tick().await;
                    stats_app.flush_stats().await;
                }
            });
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
            worker.abort();
            app.flush_stats().await;
            app.db.close().await;
        }
    }
    Ok(())
}
