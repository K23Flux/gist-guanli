use super::*;
use axum::http::Request;
use http_body_util::BodyExt;
use tower::ServiceExt;

async fn fixture() -> (tempfile::TempDir, App, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let db = store::database(dir.path()).await.unwrap();
    store::write_key(dir.path()).unwrap();
    sqlx::query("INSERT INTO admins VALUES(1,?)")
        .bind(crypto::hash_secret("local test phrase only").unwrap())
        .execute(&db)
        .await
        .unwrap();
    sqlx::query("INSERT INTO settings VALUES(1,'http://localhost:4387',60)")
        .execute(&db)
        .await
        .unwrap();
    db.close().await;
    let app = App::load(dir.path(), true).await.unwrap();
    let token = crypto::random_token();
    let csrf = crypto::random_token();
    sqlx::query("INSERT INTO sessions VALUES(?,?,?)")
        .bind(crypto::digest(&token))
        .bind(&csrf)
        .bind(store::now() + 1000)
        .execute(&app.db)
        .await
        .unwrap();
    (dir, app, token, csrf)
}
fn request(method: &str, path: &str, session: &str, csrf: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, format!("gateway_session={session}"))
        .header(header::ORIGIN, "http://localhost:4387")
        .header("x-csrf-token", csrf)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
async fn value(response: Response) -> Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}
async fn source(app: &App) -> i64 {
    sqlx::query("INSERT INTO sources(name,owner,gist_id,filename) VALUES('测试来源','example','0123456789abcdef0123456789abcdef','loon.conf')").execute(&app.db).await.unwrap().last_insert_rowid()
}
async fn create(app: &App, session: &str, csrf: &str, source_id: i64, slug: &str) -> i64 {
    let response=router(app.clone()).oneshot(request("POST","/api/admin/shares",session,csrf,json!({"source_id":source_id,"label":"本地测试","slug":slug,"filename":"loon.conf","expires_at":null}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    value(response).await["id"].as_i64().unwrap()
}
#[tokio::test]
async fn authentication_csrf_and_state_do_not_reveal_tokens() {
    let (_dir, app, session, csrf) = fixture().await;
    let response = router(app.clone())
        .oneshot(
            Request::builder()
                .uri("/api/admin/state")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let id = source(&app).await;
    let response = router(app.clone())
        .oneshot(request(
            "POST",
            "/api/admin/shares",
            &session,
            "wrong",
            json!({"source_id":id,"label":"x","slug":"test","filename":"loon.conf"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let share = create(&app, &session, &csrf, id, "one").await;
    let link = app.link(share).await.unwrap().unwrap();
    let response = router(app.clone())
        .oneshot(request(
            "GET",
            "/api/admin/state",
            &session,
            &csrf,
            json!(null),
        ))
        .await
        .unwrap();
    let body = value(response).await.to_string();
    assert!(!body.contains(link.split('/').nth(5).unwrap()));
    assert!(!body.contains("token_hash"));
    assert!(!body.contains("token_ciphertext"));
    app.db.close().await;
}
#[tokio::test]
async fn independent_shares_rotate_pause_expire_and_delete() {
    let (_dir, app, session, csrf) = fixture().await;
    let src = source(&app).await;
    let a = create(&app, &session, &csrf, src, "device-a").await;
    let b = create(&app, &session, &csrf, src, "device-b").await;
    let old = app.link(a).await.unwrap().unwrap();
    let old_token = old.split('/').nth(5).unwrap();
    assert!(authorized_source(&app, "device-a", old_token, "loon.conf")
        .await
        .is_ok());
    assert!(authorized_source(&app, "device-b", old_token, "loon.conf")
        .await
        .is_err());
    let r = router(app.clone())
        .oneshot(request(
            "POST",
            &format!("/api/admin/shares/{a}/rotate"),
            &session,
            &csrf,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(authorized_source(&app, "device-a", old_token, "loon.conf")
        .await
        .is_err());
    assert_ne!(old, app.link(a).await.unwrap().unwrap());
    let b_link = app.link(b).await.unwrap().unwrap();
    let b_token = b_link.split('/').nth(5).unwrap();
    assert!(authorized_source(&app, "device-b", b_token, "loon.conf")
        .await
        .is_ok());
    let r = router(app.clone())
        .oneshot(request(
            "POST",
            &format!("/api/admin/shares/{b}/toggle"),
            &session,
            &csrf,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(authorized_source(&app, "device-b", b_token, "loon.conf")
        .await
        .is_err());
    sqlx::query("UPDATE shares SET enabled=1,expires_at=? WHERE id=?")
        .bind(store::now() - 1)
        .bind(b)
        .execute(&app.db)
        .await
        .unwrap();
    assert!(authorized_source(&app, "device-b", b_token, "loon.conf")
        .await
        .is_err());
    // Invalid access must be rejected before making any upstream request.
    let path = url::Url::parse(&b_link).unwrap().path().to_string();
    let r = router(app.clone())
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let r = router(app.clone())
        .oneshot(request(
            "DELETE",
            &format!("/api/admin/sources/{src}"),
            &session,
            &csrf,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    for id in [a, b] {
        let r = router(app.clone())
            .oneshot(request(
                "DELETE",
                &format!("/api/admin/shares/{id}"),
                &session,
                &csrf,
                json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }
    let r = router(app.clone())
        .oneshot(request(
            "DELETE",
            &format!("/api/admin/sources/{src}"),
            &session,
            &csrf,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    app.db.close().await;
}
#[tokio::test]
async fn state_headers_and_local_qr_are_private() {
    let (_dir, app, session, csrf) = fixture().await;
    let src = source(&app).await;
    let id = create(&app, &session, &csrf, src, "phone").await;
    let response = router(app.clone())
        .oneshot(request(
            "GET",
            &format!("/api/admin/shares/{id}/qr"),
            &session,
            &csrf,
            json!(null),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    let svg = response.into_body().collect().await.unwrap().to_bytes();
    assert!(svg.starts_with(b"<?xml") || svg.starts_with(b"<svg"));
    let r = router(app.clone())
        .oneshot(request(
            "GET",
            &format!("/api/admin/shares/{id}/qr"),
            "invalid",
            &csrf,
            json!(null),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    app.db.close().await;
}
#[tokio::test]
async fn login_checks_origin_preauth_and_rotates_session() {
    let (_dir, app, _session, _csrf) = fixture().await;
    let page = router(app.clone())
        .oneshot(
            Request::builder()
                .uri("/admin/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let pre = page.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let nonce = pre.split_once('=').unwrap().1;
    let r = router(app.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &pre)
                .header(header::ORIGIN, "https://other.example.com")
                .header("x-csrf-token", nonce)
                .body(Body::from(
                    json!({"secret":"local test phrase only"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = router(app.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/admin/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &pre)
                .header(header::ORIGIN, "http://localhost:4387")
                .header("x-csrf-token", nonce)
                .body(Body::from(
                    json!({"secret":"local test phrase only"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(r
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .any(|v| v.to_str().unwrap().starts_with("gateway_session=")));
    app.db.close().await;
}
#[tokio::test]
async fn cached_content_is_exact_and_never_bypasses_revocation() {
    let (_dir, app, session, csrf) = fixture().await;
    let src = source(&app).await;
    let id = create(&app, &session, &csrf, src, "cached-device").await;
    let source = app.source(src).await.unwrap().unwrap();
    let expected =
        bytes::Bytes::from_static(b"[General]\r\n# UTF-8: \xe6\xb5\x8b\xe8\xaf\x95\r\n\x00\xff");
    app.upstream
        .seed_for_test(src, source.version, source.gist(), expected.clone())
        .await;
    let link = app.link(id).await.unwrap().unwrap();
    let path = url::Url::parse(&link).unwrap().path().to_string();
    let r = router(app.clone())
        .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.into_body().collect().await.unwrap().to_bytes(), expected);
    let r = router(app.clone())
        .oneshot(request(
            "POST",
            &format!("/api/admin/shares/{id}/rotate"),
            &session,
            &csrf,
            json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = router(app.clone())
        .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    // The cached body still exists: the rejection came from fresh authorization.
    assert_eq!(app.upstream.usage().await.0, expected.len());
    let fresh = app.link(id).await.unwrap().unwrap();
    let path = url::Url::parse(&fresh).unwrap().path().to_string();
    let r = router(app.clone())
        .oneshot(Request::builder().uri(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(r.into_body().collect().await.unwrap().to_bytes(), expected);
    app.flush_stats().await;
    let count: i64 = sqlx::query_scalar("SELECT access_count FROM shares WHERE id=?")
        .bind(id)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(count, 2);
    app.db.close().await;
}

#[tokio::test]
async fn blank_share_paths_receive_safe_defaults() {
    let (_dir, app, session, csrf) = fixture().await;
    let src = source(&app).await;
    let id = create(&app, &session, &csrf, src, "").await;
    let link = app.link(id).await.unwrap().unwrap();
    assert!(link.contains("/s/share-"));
    assert!(link.ends_with("/loon.conf"));
    app.db.close().await;
}

#[test]
fn path_segments_are_safe() {
    for bad in ["../test", "a/b", "a?b", ".hidden", "a\nb", "a b", ""] {
        assert!(!safe_segment(bad, 96));
    }
    assert!(safe_segment("loon-ios.conf", 96));
}
