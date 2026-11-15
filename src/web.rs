use crate::{
    config, crypto,
    store::{self, App, Grant, Share, Source},
    upstream::GistRef,
};
use askama::Template;
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_URL_BYTES: usize = 2048;
const BATCH_BUDGET_SECS: u64 = 90;
const MAX_EXPIRY_DAYS: i64 = 3650;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate<'a> {
    csrf: &'a str,
}
#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate<'a> {
    csrf: &'a str,
    base_url: &'a str,
}

pub struct ApiError(StatusCode, &'static str);
type ApiResult<T> = Result<T, ApiError>;
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(_: sqlx::Error) -> Self {
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "数据库暂时不可用，请稍后重试",
        )
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(_: anyhow::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "操作失败，请检查本地数据和密钥",
        )
    }
}
fn bad(message: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message)
}
fn missing() -> ApiError {
    ApiError(StatusCode::NOT_FOUND, "链接不存在或已失效")
}
fn ok() -> Json<Value> {
    Json(json!({"ok":true}))
}
fn upstream_error() -> ApiError {
    ApiError(
        StatusCode::SERVICE_UNAVAILABLE,
        "Gist 暂时无法读取，请检查地址、文件大小或稍后重试",
    )
}

pub fn router(app: App) -> Router {
    let dev = app.dev;
    Router::new()
        .route("/", get(|| async { Redirect::to("/admin") }))
        .route("/healthz", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/admin", get(dashboard))
        .route("/admin/login", get(login_page).post(login))
        .route("/admin/logout", post(logout))
        .route(
            "/static/app.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../static/app.css"),
                )
            }),
        )
        .route(
            "/static/app.js",
            get(|| async {
                (
                    [(
                        header::CONTENT_TYPE,
                        "application/javascript; charset=utf-8",
                    )],
                    include_str!("../static/app.js"),
                )
            }),
        )
        .route("/api/admin/state", get(admin_state))
        .route("/api/admin/inspect", post(inspect))
        .route("/api/admin/sources", post(create_source))
        .route("/api/admin/sources/batch", post(batch_sources))
        .route(
            "/api/admin/sources/{id}",
            put(update_source).delete(delete_source),
        )
        .route("/api/admin/sources/{id}/refresh", post(refresh_source))
        .route("/api/admin/shares", post(create_share))
        .route(
            "/api/admin/shares/{id}",
            put(update_share).delete(delete_share),
        )
        .route("/api/admin/shares/{id}/toggle", post(toggle_share))
        .route("/api/admin/shares/{id}/rotate", post(rotate_share))
        .route("/api/admin/shares/{id}/reveal", post(reveal_share))
        .route("/api/admin/shares/{id}/qr", get(qr_share))
        .route("/api/admin/settings", put(update_settings))
        .route("/api/admin/credentials", post(change_secret))
        .route("/s/{slug}/{token}/{filename}", get(subscription))
        .fallback(|| async { missing() })
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(middleware::from_fn(move |request, next| {
            security_headers(dev, request, next)
        }))
        .with_state(app)
}
async fn security_headers(dev: bool, request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for(k,v) in [
  ("cache-control","no-store"),("referrer-policy","no-referrer"),("x-content-type-options","nosniff"),
  ("x-frame-options","DENY"),("permissions-policy","camera=(), microphone=(), geolocation=()"),
  ("cross-origin-resource-policy","same-origin"),("x-robots-tag","noindex, nofollow"),
  ("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'"),
 ]{response.headers_mut().insert(axum::http::HeaderName::from_static(k),HeaderValue::from_static(v));}
    if !dev {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000"),
        );
    }
    response
}
fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|s| s.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty() && v.len() <= 128)
}
fn client_key(headers: &HeaderMap, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(value) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        {
            if let Some(first) = value.split(',').next() {
                if let Ok(ip) = first.trim().parse::<std::net::IpAddr>() {
                    return ip.to_string();
                }
            }
        }
        if let Some(value) = headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
        {
            if let Ok(ip) = value.trim().parse::<std::net::IpAddr>() {
                return ip.to_string();
            }
        }
    }
    "direct".to_owned()
}
fn session_name(dev: bool) -> &'static str {
    if dev {
        "gateway_session"
    } else {
        "__Host-gateway_session"
    }
}
fn preauth_name(dev: bool) -> &'static str {
    if dev {
        "gateway_preauth"
    } else {
        "__Host-gateway_preauth"
    }
}
fn set_cookie(name: &str, value: &str, age: i64, dev: bool) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{}",
        if dev { "" } else { "; Secure" }
    ))
    .expect("generated cookie is ASCII")
}
async fn authenticated(app: &App, headers: &HeaderMap) -> ApiResult<String> {
    let token = cookie(headers, session_name(app.dev))
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "请先登录"))?;
    let session = app
        .session(&token)
        .await?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "登录已过期，请重新登录"))?;
    Ok(session.csrf)
}
async fn origin_matches(app: &App, headers: &HeaderMap) -> ApiResult<()> {
    let base = app.settings().await?.base_url;
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(base.as_str()) {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "请求来源不匹配，请通过设置的对外地址访问",
        ));
    }
    Ok(())
}
async fn mutation(app: &App, headers: &HeaderMap) -> ApiResult<()> {
    let csrf = authenticated(app, headers).await?;
    origin_matches(app, headers).await?;
    let actual = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crypto::matches(actual, &crypto::digest(&csrf)) {
        return Err(ApiError(StatusCode::FORBIDDEN, "页面已过期，请刷新后重试"));
    }
    Ok(())
}
async fn login_page(State(app): State<App>) -> ApiResult<Response> {
    let csrf = crypto::random_token();
    let html = LoginTemplate { csrf: &csrf }
        .render()
        .map_err(|_| bad("页面生成失败"))?;
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        set_cookie(preauth_name(app.dev), &csrf, 600, app.dev),
    );
    Ok(response)
}
#[derive(Deserialize)]
struct LoginInput {
    secret: String,
}
async fn login(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<LoginInput>,
) -> ApiResult<Response> {
    origin_matches(&app, &headers).await?;
    let pre = cookie(&headers, preauth_name(app.dev))
        .ok_or(ApiError(StatusCode::FORBIDDEN, "请刷新登录页"))?;
    let csrf = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crypto::matches(csrf, &crypto::digest(&pre)) {
        return Err(ApiError(StatusCode::FORBIDDEN, "请刷新登录页"));
    }
    let client = client_key(&headers, app.trust_proxy);
    let _permit = app
        .login_gate
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "正在处理登录，请稍后重试"))?;
    {
        let now = store::now();
        let mut attempts = app.attempts.lock().await;
        attempts.retain(|_, times| {
            times.retain(|t| *t > now - 300);
            !times.is_empty()
        });
        let times = attempts.entry(client.clone()).or_default();
        if times.len() >= 5 {
            return Err(ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "登录尝试过多，请 5 分钟后重试",
            ));
        }
        times.push(now);
    }
    if input.secret.len() > 1024 {
        return Err(bad("口令过长"));
    }
    let stored: String = sqlx::query_scalar("SELECT pass_hash FROM admins WHERE id=1")
        .fetch_one(&app.db)
        .await?;
    let valid = tokio::task::spawn_blocking(move || crypto::verify_secret(&input.secret, &stored))
        .await
        .map_err(|_| bad("登录处理失败"))?;
    if !valid {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "口令不正确"));
    }
    app.attempts.lock().await.remove(&client);
    let token = crypto::random_token();
    let csrf = crypto::random_token();
    let mut tx = app.db.begin().await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at<=?")
        .bind(store::now())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions ORDER BY expires_at DESC LIMIT -1 OFFSET 7)").execute(&mut *tx).await?;
    sqlx::query("INSERT INTO sessions(token_hash,csrf,expires_at) VALUES(?,?,?)")
        .bind(crypto::digest(&token))
        .bind(csrf)
        .bind(store::now() + 43200)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut response = ok().into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(session_name(app.dev), &token, 43200, app.dev),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        set_cookie(preauth_name(app.dev), "", 0, app.dev),
    );
    Ok(response)
}
async fn logout(State(app): State<App>, headers: HeaderMap) -> ApiResult<Response> {
    mutation(&app, &headers).await?;
    if let Some(token) = cookie(&headers, session_name(app.dev)) {
        sqlx::query("DELETE FROM sessions WHERE token_hash=?")
            .bind(crypto::digest(&token))
            .execute(&app.db)
            .await?;
    }
    let mut r = ok().into_response();
    r.headers_mut().insert(
        header::SET_COOKIE,
        set_cookie(session_name(app.dev), "", 0, app.dev),
    );
    Ok(r)
}
async fn dashboard(State(app): State<App>, headers: HeaderMap) -> ApiResult<Response> {
    let csrf = match authenticated(&app, &headers).await {
        Ok(c) => c,
        Err(e) if e.0 == StatusCode::UNAUTHORIZED => {
            return Ok(Redirect::to("/admin/login").into_response())
        }
        Err(e) => return Err(e),
    };
    let base = app.settings().await?.base_url;
    Ok(Html(
        DashboardTemplate {
            csrf: &csrf,
            base_url: &base,
        }
        .render()
        .map_err(|_| bad("页面生成失败"))?,
    )
    .into_response())
}
async fn admin_state(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let csrf = authenticated(&app, &headers).await?;
    let sources:Vec<Source>=sqlx::query_as("SELECT s.*,(SELECT COUNT(*) FROM shares sh WHERE sh.source_id=s.id) AS share_count FROM sources s ORDER BY s.id DESC").fetch_all(&app.db).await?;
    let shares:Vec<Share>=sqlx::query_as("SELECT sh.id,sh.source_id,sh.label,sh.slug,sh.filename,sh.enabled,sh.expires_at,sh.last_access,sh.access_count,s.name AS source_name FROM shares sh JOIN sources s ON s.id=sh.source_id ORDER BY sh.id DESC").fetch_all(&app.db).await?;
    let settings = app.settings().await?;
    let (bytes, entries) = app.upstream.usage().await;
    Ok(Json(
        json!({"sources":sources,"shares":shares,"settings":settings,"csrf":csrf,"cache":{"bytes":bytes,"entries":entries,"limit_bytes":store::CACHE_LIMIT}}),
    ))
}
#[derive(Deserialize)]
struct InspectInput {
    url: String,
}
async fn inspect(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<InspectInput>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    if input.url.len() > 2048 {
        return Err(bad("Gist 地址过长"));
    }
    let result = app
        .upstream
        .inspect(&input.url)
        .await
        .map_err(|_| bad("无法识别或读取 Gist，请检查地址及文件"))?;
    Ok(Json(
        serde_json::to_value(result).map_err(|_| bad("来源读取失败"))?,
    ))
}
#[derive(Deserialize, Clone)]
struct SourceInput {
    name: String,
    url: String,
    filename: String,
    #[serde(default)]
    follow_latest: bool,
}
fn short_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.chars().count() <= max && !value.chars().any(char::is_control)
}
async fn checked_source(app: &App, input: &SourceInput) -> ApiResult<GistRef> {
    if !short_text(&input.name, 80) || input.url.len() > MAX_URL_BYTES {
        return Err(bad("名称应为 1～80 个字符，Gist 地址最长 2048 字节"));
    }
    let result = app
        .upstream
        .inspect(input.url.trim())
        .await
        .map_err(|_| bad("Gist 地址或文件无效"))?;
    if result.pinned && !input.follow_latest {
        return Err(bad("该地址固定了历史版本，请确认改为跟随最新内容"));
    }
    if !result.files.contains(&input.filename) {
        return Err(bad("请选择 Gist 中实际存在的文件"));
    }
    let gist = GistRef {
        owner: result.owner,
        gist_id: result.gist_id,
        filename: input.filename.clone(),
    };
    let validation_version = rand::random::<i64>();
    app.upstream
        .get(0, validation_version, &gist, 0)
        .await
        .map_err(|_| upstream_error())?;
    app.upstream.invalidate(0).await;
    Ok(gist)
}
async fn insert_source(app: &App, input: SourceInput) -> ApiResult<i64> {
    let gist = checked_source(app, &input).await?;
    let mut tx = app.db.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sources")
        .fetch_one(&mut *tx)
        .await?;
    if count >= 512 {
        return Err(bad("已达到 512 个来源上限"));
    }
    let id =
        sqlx::query("INSERT INTO sources(name,owner,gist_id,filename,last_ok) VALUES(?,?,?,?,?)")
            .bind(input.name.trim())
            .bind(gist.owner)
            .bind(gist.gist_id)
            .bind(gist.filename)
            .bind(store::now())
            .execute(&mut *tx)
            .await?
            .last_insert_rowid();
    tx.commit().await?;
    Ok(id)
}
async fn create_source(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<SourceInput>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let id = insert_source(&app, input).await?;
    Ok(Json(json!({"ok":true,"id":id})))
}
async fn update_source(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<SourceInput>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    if app.source(id).await?.is_none() {
        return Err(missing());
    }
    let gist = checked_source(&app, &input).await?;
    let result=sqlx::query("UPDATE sources SET name=?,owner=?,gist_id=?,filename=?,version=version+1,last_ok=?,last_error=NULL WHERE id=?").bind(input.name.trim()).bind(gist.owner).bind(gist.gist_id).bind(gist.filename).bind(store::now()).bind(id).execute(&app.db).await?;
    if result.rows_affected() == 0 {
        return Err(missing());
    }
    app.upstream.invalidate(id).await;
    Ok(ok())
}
async fn delete_source(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let result = sqlx::query(
        "DELETE FROM sources WHERE id=? AND NOT EXISTS (SELECT 1 FROM shares WHERE source_id=?)",
    )
    .bind(id)
    .bind(id)
    .execute(&app.db)
    .await?;
    if result.rows_affected() == 0 {
        if app.source(id).await?.is_some() {
            return Err(bad("该来源仍有关联链接，请先删除或改绑这些链接"));
        }
        return Err(missing());
    }
    app.upstream.invalidate(id).await;
    Ok(ok())
}
async fn refresh_source(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let source = app.source(id).await?.ok_or_else(missing)?;
    app.upstream.invalidate(id).await;
    match app
        .upstream
        .get(id, source.version, &source.gist(), 0)
        .await
    {
        Ok(_) => {
            sqlx::query("UPDATE sources SET last_ok=?,last_error=NULL WHERE id=? AND version=?")
                .bind(store::now())
                .bind(id)
                .bind(source.version)
                .execute(&app.db)
                .await?;
            Ok(ok())
        }
        Err(_) => {
            let _=sqlx::query("UPDATE sources SET last_error='读取失败，请检查 Gist、网络或大小限制' WHERE id=? AND version=?").bind(id).bind(source.version).execute(&app.db).await;
            Err(upstream_error())
        }
    }
}
#[derive(Deserialize)]
struct BatchInput {
    urls: Vec<String>,
}
async fn batch_sources(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<BatchInput>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    if input.urls.is_empty() || input.urls.len() > 50 {
        return Err(bad("每批请输入 1～50 条 raw 地址"));
    }
    let mut results = Vec::with_capacity(input.urls.len());
    let started = std::time::Instant::now();
    let mut over_budget = false;
    for raw in input.urls {
        let raw = raw.trim().to_owned();
        if over_budget || started.elapsed() > std::time::Duration::from_secs(BATCH_BUDGET_SECS) {
            over_budget = true;
            results.push(
                json!({"ok":false,"url":raw,"error":"本批等待时间较长，未处理的地址请分批重试"}),
            );
            continue;
        }
        if raw.len() > MAX_URL_BYTES {
            results.push(json!({"ok":false,"url":raw,"error":"Gist 地址最长 2048 字节"}));
            continue;
        }
        let input = match url::Url::parse(&raw) {
            Ok(url) if url.host_str() == Some("gist.githubusercontent.com") => {
                match app.upstream.inspect(&raw).await {
                    Ok(result) if !result.pinned => result.selected.map(|filename| SourceInput {
                        name: filename.clone(),
                        url: raw.clone(),
                        filename,
                        follow_latest: false,
                    }),
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(input) = input {
            let name = input.name.clone();
            match insert_source(&app, input).await {
                Ok(id) => results.push(json!({"ok":true,"id":id,"name":name,"url":raw})),
                Err(e) => results.push(json!({"ok":false,"url":raw,"error":e.1})),
            }
        } else {
            results.push(json!({"ok":false,"url":raw,"error":"请使用不固定版本的 raw 地址；多文件页面或历史版本请单条导入"}));
        }
    }
    Ok(Json(json!({"results":results})))
}
#[derive(Deserialize)]
struct ShareInput {
    source_id: i64,
    label: String,
    slug: String,
    filename: String,
    expires_at: Option<i64>,
    #[serde(default = "yes")]
    enabled: bool,
}
fn yes() -> bool {
    true
}
fn valid_expiry(value: Option<i64>) -> bool {
    let now = store::now();
    value.is_none_or(|t| t > now && t <= now.saturating_add(MAX_EXPIRY_DAYS * 86_400))
}
fn safe_segment(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && !s.starts_with('.')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_- .".contains(&c) && c != b' ')
}
async fn default_share(app: &App, mut input: ShareInput) -> ApiResult<ShareInput> {
    if !valid_expiry(input.expires_at) {
        return Err(bad("到期时间需要是未来的有效时间"));
    }
    let source = app
        .source(input.source_id)
        .await?
        .ok_or(bad("请选择有效来源"))?;
    if input.slug.trim().is_empty() {
        input.slug = format!("share-{}", &crypto::random_token()[..12]);
    }
    if input.filename.trim().is_empty() {
        input.filename = if safe_segment(&source.filename, 96) {
            source.filename
        } else {
            "subscription.conf".to_owned()
        };
    }
    Ok(input)
}
async fn validate_share(app: &App, input: &ShareInput) -> ApiResult<()> {
    if !short_text(&input.label, 120)
        || !safe_segment(&input.slug, 64)
        || !safe_segment(&input.filename, 96)
    {
        return Err(bad(
            "备注最长 120 字；后缀和文件名只允许英文字母、数字、点、下划线和连字符",
        ));
    }
    if app.source(input.source_id).await?.is_none() {
        return Err(bad("请选择有效来源"));
    }
    Ok(())
}
fn share_db_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(ref e) = error {
        if e.is_unique_violation() {
            return bad("该自定义后缀已使用，请换一个");
        }
        if e.is_foreign_key_violation() {
            return bad("来源已被删除，请重新选择");
        }
    }
    error.into()
}
async fn create_share(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<ShareInput>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let input = default_share(&app, input).await?;
    validate_share(&app, &input).await?;
    let token = crypto::random_token();
    let encrypted = app.crypto.seal(&token)?;
    let mut tx = app.db.begin().await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM shares")
        .fetch_one(&mut *tx)
        .await?;
    if count >= 2048 {
        return Err(bad("已达到 2048 条分享链接上限"));
    }
    let id=sqlx::query("INSERT INTO shares(source_id,label,slug,filename,token_hash,token_ciphertext,enabled,expires_at) VALUES(?,?,?,?,?,?,?,?)").bind(input.source_id).bind(input.label.trim()).bind(input.slug).bind(input.filename).bind(crypto::digest(&token)).bind(encrypted).bind(input.enabled).bind(input.expires_at).execute(&mut *tx).await.map_err(share_db_error)?.last_insert_rowid();
    tx.commit().await?;
    Ok(Json(json!({"ok":true,"id":id})))
}
async fn update_share(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<ShareInput>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let current_source: Option<i64> = sqlx::query_scalar("SELECT source_id FROM shares WHERE id=?")
        .bind(id)
        .fetch_optional(&app.db)
        .await?;
    let Some(current_source) = current_source else {
        return Err(missing());
    };
    if input.source_id != current_source {
        return Err(bad("分享来源不可更改；如需换源请新建分享"));
    }
    let input = default_share(&app, input).await?;
    validate_share(&app, &input).await?;
    let r = sqlx::query(
        "UPDATE shares SET source_id=?,label=?,slug=?,filename=?,enabled=?,expires_at=? WHERE id=?",
    )
    .bind(input.source_id)
    .bind(input.label.trim())
    .bind(input.slug)
    .bind(input.filename)
    .bind(input.enabled)
    .bind(input.expires_at)
    .bind(id)
    .execute(&app.db)
    .await
    .map_err(share_db_error)?;
    if r.rows_affected() == 0 {
        return Err(missing());
    }
    Ok(ok())
}
async fn toggle_share(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let r = sqlx::query("UPDATE shares SET enabled=NOT enabled WHERE id=?")
        .bind(id)
        .execute(&app.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(missing());
    }
    Ok(ok())
}
async fn rotate_share(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let token = crypto::random_token();
    let encrypted = app.crypto.seal(&token)?;
    let r = sqlx::query("UPDATE shares SET token_hash=?,token_ciphertext=? WHERE id=?")
        .bind(crypto::digest(&token))
        .bind(encrypted)
        .bind(id)
        .execute(&app.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(missing());
    }
    Ok(ok())
}
async fn delete_share(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let r = sqlx::query("DELETE FROM shares WHERE id=?")
        .bind(id)
        .execute(&app.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(missing());
    }
    app.stats.lock().await.remove(&id);
    Ok(ok())
}
async fn reveal_share(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let url = app.link(id).await?.ok_or_else(missing)?;
    Ok(Json(json!({"url":url})))
}
async fn qr_share(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Response> {
    authenticated(&app, &headers).await?;
    let url = app.link(id).await?.ok_or_else(missing)?;
    let code = qrcode::QrCode::new(url.as_bytes()).map_err(|_| bad("链接过长，无法生成二维码"))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(256, 256)
        .build();
    Ok(([(header::CONTENT_TYPE, "image/svg+xml")], svg).into_response())
}
#[derive(Deserialize)]
struct SettingsInput {
    base_url: String,
    cache_ttl_secs: i64,
}
async fn update_settings(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<SettingsInput>,
) -> ApiResult<Json<Value>> {
    mutation(&app, &headers).await?;
    let base = config::normalize_base(&input.base_url, app.dev)
        .map_err(|_| bad("对外地址需要为 HTTPS 根地址；开发模式只允许本机 HTTP"))?;
    if !(10..=3600).contains(&input.cache_ttl_secs) {
        return Err(bad("缓存时间需要在 10～3600 秒之间"));
    }
    sqlx::query("UPDATE settings SET base_url=?,cache_ttl_secs=? WHERE id=1")
        .bind(base)
        .bind(input.cache_ttl_secs)
        .execute(&app.db)
        .await?;
    Ok(ok())
}
#[derive(Deserialize)]
struct SecretInput {
    current_secret: String,
    new_secret: String,
}
async fn change_secret(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<SecretInput>,
) -> ApiResult<Response> {
    mutation(&app, &headers).await?;
    if input.new_secret.chars().count() < 12
        || input.new_secret.len() > 1024
        || input.current_secret.len() > 1024
    {
        return Err(bad("新口令至少 12 个字符，最多 1024 字节"));
    }
    let _permit = app
        .login_gate
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS, "正在处理认证，请稍后重试"))?;
    let stored: String = sqlx::query_scalar("SELECT pass_hash FROM admins WHERE id=1")
        .fetch_one(&app.db)
        .await?;
    let hashed = tokio::task::spawn_blocking(move || {
        if !crypto::verify_secret(&input.current_secret, &stored) {
            return None;
        }
        crypto::hash_secret(&input.new_secret).ok()
    })
    .await
    .map_err(|_| bad("口令处理失败"))?
    .ok_or(bad("当前口令不正确"))?;
    let mut tx = app.db.begin().await?;
    sqlx::query("UPDATE admins SET pass_hash=? WHERE id=1")
        .bind(hashed)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM sessions")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let mut response = ok().into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        set_cookie(session_name(app.dev), "", 0, app.dev),
    );
    Ok(response)
}
async fn authorized_source(
    app: &App,
    slug: &str,
    token: &str,
    filename: &str,
) -> ApiResult<(Grant, Source)> {
    // A single SQLite statement observes credentials, binding and source version
    // from the same snapshot, including the final check after upstream I/O.
    let row = sqlx::query("SELECT sh.id AS share_id,sh.source_id,sh.token_hash,sh.enabled,sh.expires_at,sh.filename AS output_filename,s.name,s.owner,s.gist_id,s.filename AS source_filename,s.version,s.last_ok,s.last_error FROM shares sh JOIN sources s ON s.id=sh.source_id WHERE sh.slug=?")
        .bind(slug).fetch_optional(&app.db).await?.ok_or_else(missing)?;
    let grant = Grant {
        id: row.try_get("share_id")?,
        source_id: row.try_get("source_id")?,
        token_hash: row.try_get("token_hash")?,
        enabled: row.try_get("enabled")?,
        expires_at: row.try_get("expires_at")?,
        filename: row.try_get("output_filename")?,
    };
    if !grant.accepts(token, filename) {
        return Err(missing());
    }
    let source = Source {
        id: grant.source_id,
        name: row.try_get("name")?,
        owner: row.try_get("owner")?,
        gist_id: row.try_get("gist_id")?,
        filename: row.try_get("source_filename")?,
        version: row.try_get("version")?,
        last_ok: row.try_get("last_ok")?,
        last_error: row.try_get("last_error")?,
        share_count: 0,
    };
    Ok((grant, source))
}
async fn subscription(
    State(app): State<App>,
    Path((slug, token, filename)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    if slug.len() > 64 || token.len() != 43 || filename.len() > 96 {
        return Err(missing());
    }
    let (grant, source) = authorized_source(&app, &slug, &token, &filename).await?;
    let delivery = app.deliveries.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "当前更新请求较多，请稍后重试",
        )
    })?;
    let ttl = app.settings().await?.cache_ttl_secs.clamp(10, 3600) as u64;
    let bytes = match app
        .upstream
        .get(source.id, source.version, &source.gist(), ttl)
        .await
    {
        Ok(b) => {
            app.record_health(source.id, source.version, true).await;
            b
        }
        Err(_) => {
            app.record_health(source.id, source.version, false).await;
            return Err(upstream_error());
        }
    };
    // The last authorization read is the decision point; never authorize from a body cache.
    let (current, current_source) = authorized_source(&app, &slug, &token, &filename).await?;
    if current.id != grant.id
        || current.source_id != source.id
        || current_source.version != source.version
    {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "来源刚刚更新，请重新获取",
        ));
    }
    app.record(grant.id).await;
    // Bound simultaneous responses as well as upstream fetches. Hold the permit
    // while streaming small frames instead of cloning complete config bodies.
    let stream =
        futures_util::stream::unfold((bytes, delivery), |(mut bytes, permit)| async move {
            if bytes.is_empty() {
                return None;
            }
            let length = bytes.len().min(16 * 1024);
            let chunk = bytes.split_to(length);
            Some((Ok::<_, std::convert::Infallible>(chunk), (bytes, permit)))
        });
    Ok((
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        Body::from_stream(stream),
    )
        .into_response())
}

#[cfg(test)]
mod tests;
