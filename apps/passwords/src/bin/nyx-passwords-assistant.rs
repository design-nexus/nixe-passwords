//! Nyx Assistant's Passwords ability: an MCP server on stdin/stdout (one JSON-RPC
//! message per line) with two tools.
//!
//! - `passwords.find`: logins by name or site, as names, usernames and sites only.
//! - `passwords.copy`: puts a login's username, password or one-time code on the
//!   clipboard through the daemon. The value never comes back here, so the assistant
//!   never sees it: the answer is only that it was copied.
//!
//! The daemon answers this program only when "Nyx Assistant" is turned on in Passwords'
//! settings, and the assistant asks for a key press before each call
//! (`assistant-policy`'s `Secrets` capability).

use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use nyx_passwords_proto::{self as proto, Item};
use serde_json::{Value, json};

/// The assistant's frame limit.
const MAX_LINE: usize = 1024 * 1024;
const FIND_LIMIT: u32 = 10;

fn main() {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(_) => std::process::exit(1),
    };
    let mut conn: Option<zbus::Connection> = None;
    let mut out = std::io::stdout().lock();
    let mut input = std::io::stdin().lock();
    loop {
        // Read at most one frame's worth, so an over-long line can't grow without end.
        let mut raw = Vec::new();
        match (&mut input).take(MAX_LINE as u64 + 1).read_until(b'\n', &mut raw) {
            Ok(0) | Err(_) => break,
            Ok(_) if raw.len() > MAX_LINE => break,
            Ok(_) => {}
        }
        let Ok(line) = String::from_utf8(raw) else { continue };
        let Ok(message) = serde_json::from_str::<Value>(&line) else { continue };
        // Notifications (initialized, cancelled) need no answer; calls finish quickly.
        let Some(id) = message.get("id").cloned() else { continue };
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let reply = match message["method"].as_str().unwrap_or_default() {
            "initialize" => Ok(json!({
                "protocolVersion": "2025-11-25",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "nyx-passwords", "version": env!("CARGO_PKG_VERSION")},
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => Ok(rt.block_on(call(&mut conn, &params))),
            _ => Err("unsupported method"),
        };
        let answer = match reply {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": e}}),
        };
        if writeln!(out, "{answer}").and_then(|_| out.flush()).is_err() {
            break;
        }
    }
}

fn tools() -> Value {
    // Routed voice requests add `request` (the words said) to the arguments.
    json!([
        {
            "name": "passwords.find",
            "description": "Find logins in Nyx Passwords by name or website. Returns names, usernames and sites, never passwords.",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 256}, "request": {"type": "string"}},
                "required": ["query"],
                "additionalProperties": false,
            },
        },
        {
            "name": "passwords.copy",
            "description": "Copy a login's username, password or current one-time code to the clipboard (it clears itself). Give the login's id from passwords.find, or a query that matches exactly one login. The value is never returned.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "query": {"type": "string", "minLength": 1, "maxLength": 256},
                    "field": {"type": "string", "enum": ["username", "password", "code"]},
                    "request": {"type": "string"},
                },
                "required": ["field"],
                "additionalProperties": false,
            },
        },
    ])
}

/// A tool's result: structured data on success, a message with `isError` otherwise.
fn result(outcome: Result<Value, String>) -> Value {
    match outcome {
        Ok(data) => json!({"content": [{"type": "text", "text": data.to_string()}], "structuredContent": data, "isError": false}),
        Err(message) => json!({"content": [{"type": "text", "text": message}], "isError": true}),
    }
}

async fn call(conn: &mut Option<zbus::Connection>, params: &Value) -> Value {
    let args = &params["arguments"];
    let outcome = match params["name"].as_str().unwrap_or_default() {
        "passwords.find" => find(conn, args).await,
        "passwords.copy" => copy(conn, args).await,
        _ => Err("unknown tool".to_string()),
    };
    result(outcome)
}

fn described(item: &Item) -> Value {
    let (id, name, username, host, has_code, kind) = item;
    json!({"id": id, "name": name, "username": username, "site": host, "kind": kind, "has_code": has_code})
}

async fn find(conn: &mut Option<zbus::Connection>, args: &Value) -> Result<Value, String> {
    let query = args["query"].as_str().map(str::trim).filter(|q| !q.is_empty()).ok_or("say what to look for")?;
    let items = search(conn, query, FIND_LIMIT).await?;
    Ok(json!({"logins": items.iter().map(described).collect::<Vec<_>>()}))
}

async fn copy(conn: &mut Option<zbus::Connection>, args: &Value) -> Result<Value, String> {
    let field = match args["field"].as_str() {
        Some("username") => proto::field::USERNAME,
        Some("password") => proto::field::PASSWORD,
        Some("code") => proto::field::TOTP,
        _ => return Err("field must be username, password or code".into()),
    };
    let (id, name) = match (args["id"].as_str(), args["query"].as_str().map(str::trim).filter(|q| !q.is_empty())) {
        (Some(id), _) => (id.to_string(), None),
        (None, Some(query)) => {
            let items = search(conn, query, 5).await?;
            match items.as_slice() {
                [] => return Err(format!("no login matches “{query}”")),
                [one] => (one.0.clone(), Some(one.1.clone())),
                many => {
                    let names: Vec<String> = many.iter().map(|i| format!("{} ({})", i.1, i.2)).collect();
                    return Err(format!("several logins match: {}; say which", names.join(", ")));
                }
            }
        }
        (None, None) => return Err("give the login's id or a query".into()),
    };
    let reply = request(conn, "Copy", &(id.as_str(), field)).await?;
    let seconds: u32 = reply.body().deserialize().map_err(|_| "unexpected answer".to_string())?;
    Ok(json!({"copied": args["field"], "login": name, "clears_in_seconds": seconds}))
}

async fn search(conn: &mut Option<zbus::Connection>, query: &str, limit: u32) -> Result<Vec<Item>, String> {
    let reply = request(conn, "Search", &(query, limit)).await?;
    reply.body().deserialize::<Vec<Item>>().map_err(|_| "unexpected answer".to_string())
}

/// Calls the daemon, connecting first (and again once if it restarted). Errors are the
/// daemon's, in words the assistant can say.
async fn request<B>(conn: &mut Option<zbus::Connection>, method: &str, body: &B) -> Result<zbus::Message, String>
where
    B: serde::Serialize + zbus::zvariant::DynamicType,
{
    for attempt in 0..2 {
        if conn.is_none() {
            *conn = connect().await;
        }
        let Some(c) = conn.as_ref() else { break };
        match c.call_method(None::<&str>, proto::OBJECT_PATH, Some(proto::INTERFACE), method, body).await {
            Ok(msg) => return Ok(msg),
            Err(zbus::Error::InputOutput(_)) if attempt == 0 => *conn = None,
            Err(zbus::Error::MethodError(name, message, _)) => {
                return Err(match proto::Error::from_name(name.as_str()) {
                    Some(proto::Error::Locked) => "Nyx Passwords is locked: unlock it first".into(),
                    Some(proto::Error::LoggedOut) => "Nyx Passwords isn't signed in".into(),
                    Some(proto::Error::Reprompt) => "that login asks for the master password: copy it in Passwords".into(),
                    Some(proto::Error::RateLimited) => "too many copies; wait a minute".into(),
                    _ => message.unwrap_or_else(|| "Nyx Passwords refused".into()),
                });
            }
            Err(_) => {
                *conn = None;
                break;
            }
        }
    }
    Err("Nyx Passwords isn't running: open it and unlock it first".into())
}

/// The daemon's socket. The assistant may start this program with a cleared
/// environment, so without `XDG_RUNTIME_DIR` it's looked for in the usual place.
fn socket() -> PathBuf {
    proto::socket_path().unwrap_or_else(|| {
        // SAFETY: getuid has no preconditions.
        PathBuf::from(format!("/run/user/{}/nyx-passwords/bus", unsafe { libc::getuid() }))
    })
}

async fn connect() -> Option<zbus::Connection> {
    let stream = tokio::net::UnixStream::connect(socket()).await.ok()?;
    let build = zbus::connection::Builder::unix_stream(stream).p2p().build();
    tokio::time::timeout(Duration::from_secs(5), build).await.ok()?.ok()
}
