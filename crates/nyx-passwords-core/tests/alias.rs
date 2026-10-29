//! The email alias services, against a stand-in that answers as each does and records
//! what it was asked. No real service is contacted.

use nyx_passwords_core::alias::{self, UsernameError, UsernameKind, UsernameRules};
use nyx_passwords_core::secret::Secret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Answers each request by its path and keeps the requests (lowercased headers).
async fn stand_in() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = listener.accept().await else { return };
            let mut buf = vec![0u8; 16384];
            let n = conn.read(&mut buf).await.unwrap();
            let mut request = String::from_utf8_lossy(&buf[..n]).to_string();
            // The body may come in a second packet.
            if !request.contains("\r\n\r\n{") && request.to_lowercase().contains("content-length") {
                let n = conn.read(&mut buf).await.unwrap_or(0);
                request.push_str(&String::from_utf8_lossy(&buf[..n]));
            }
            let path = request.split_whitespace().nth(1).unwrap_or_default().to_string();
            let (status, body) = match path.split('?').next().unwrap() {
                "/api/alias/random/new" => (201, r#"{"alias":"x1@simplelogin.example"}"#.to_string()),
                "/api/v1/aliases" => (201, r#"{"data":{"email":"x2@addy.example"}}"#.into()),
                "/api/v1/relayaddresses/" => (201, r#"{"full_address":"x3@mozmail.com"}"#.into()),
                "/api/email/addresses" if request.to_lowercase().contains("bearer bad") => (401, "{}".into()),
                "/api/email/addresses" => (201, r#"{"address":"x4"}"#.into()),
                "/jmap/session" => (200, r#"{"primaryAccounts":{"https://www.fastmail.com/dev/maskedemail":"acct1"}}"#.into()),
                "/jmap/api/" => (
                    200,
                    r#"{"methodResponses":[["MaskedEmail/set",{"created":{"new":{"email":"x5@fastmail.example"}}},"0"]]}"#.into(),
                ),
                p if p.starts_with("/v1/domains/") => (200, r#"{"name":"x6","domain":{"name":"fwd.example"}}"#.into()),
                _ => (404, "{}".into()),
            };
            log.lock().unwrap().push(request.to_lowercase());
            let reply = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            conn.write_all(reply.as_bytes()).await.unwrap();
        }
    });
    (base, seen)
}

#[tokio::test]
async fn each_service_makes_an_alias() {
    let (base, seen) = stand_in().await;
    let token = Secret::new("tok123");
    let site = Some("https://login.github.com/session");
    let mut rules =
        UsernameRules { kind: UsernameKind::Forwarded, service_domain: "fwd.example".into(), ..UsernameRules::default() };
    for (service, expected, header) in [
        ("simplelogin", "x1@simplelogin.example", "authentication: tok123"),
        ("addy", "x2@addy.example", "authorization: bearer tok123"),
        ("relay", "x3@mozmail.com", "authorization: token tok123"),
        ("duckduckgo", "x4@duck.com", "authorization: bearer tok123"),
        ("fastmail", "x5@fastmail.example", "authorization: bearer tok123"),
        ("forwardemail", "x6@fwd.example", "authorization: basic "),
    ] {
        rules.service = service.into();
        let made = alias::forwarded(&rules, &token, site, Some(&base)).await.unwrap_or_else(|e| panic!("{service}: {e}"));
        assert_eq!(made.expose(), expected, "{service}");
        let last = seen.lock().unwrap().last().cloned().unwrap();
        assert!(last.contains(header), "{service}: {last}");
        if service != "duckduckgo" {
            assert!(last.contains("github.com"), "{service} names the site: {last}");
        }
    }
    // SimpleLogin gets the site as `hostname`.
    assert!(seen.lock().unwrap()[0].contains("?hostname=github.com"));

    rules.service = "duckduckgo".into();
    let refused = alias::forwarded(&rules, &Secret::new("bad"), site, Some(&base)).await;
    assert_eq!(refused.err(), Some(UsernameError::Service("the service refused the token".into())));
    assert_eq!(alias::forwarded(&rules, &Secret::new(""), site, Some(&base)).await.err(), Some(UsernameError::NoToken));
    rules.service = "addy".into();
    rules.service_domain.clear();
    assert!(matches!(alias::forwarded(&rules, &token, site, Some(&base)).await, Err(UsernameError::Incomplete(_))));
}
