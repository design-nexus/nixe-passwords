//! Live sync: Vaultwarden's notification hub (`/notifications/hub`, SignalR over a
//! WebSocket) says when the vault changed elsewhere, so the daemon can sync then
//! instead of waiting for its timer. Vaultwarden speaks only SignalR's MessagePack
//! protocol. The messages carry ids and dates, never vault data.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use rmpv::Value;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{Connector, MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use crate::api::{ApiError, Server};
use crate::secret::Secret;

/// SignalR ends each text message with this.
const RECORD_SEPARATOR: char = '\u{1e}';
/// A SignalR ping when the hub has been quiet this long, so the connection stays up
/// through proxies; the daemon also hears `Idle` then.
const QUIET: Duration = Duration::from_secs(15);
/// The largest message read from the hub.
const MESSAGE_MAX: usize = 64 * 1024;

/// What the hub said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Items, folders, collections, settings or keys changed on another device.
    Changed,
    /// The account was signed out everywhere (a password or key change elsewhere).
    LoggedOut,
    /// Another device asks to sign in with this one's approval (its request id).
    AuthRequest(String),
    /// Nothing for a while; a ping was sent.
    Idle,
}

/// The hub's update types (Bitwarden's `PushType`).
fn event_of(kind: i64, payload: &Value) -> Option<Event> {
    match kind {
        // Ciphers, folders, the whole vault, org keys, settings.
        0..=10 => Some(Event::Changed),
        11 => Some(Event::LoggedOut),
        15 => field(payload, "Id").and_then(Value::as_str).map(|id| Event::AuthRequest(id.to_string())),
        // Sends (12–14), auth responses (16) and anything newer: not for this client.
        _ => None,
    }
}

pub struct Hub {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    device: Uuid,
    pending: VecDeque<Event>,
}

impl Server {
    /// Connects to the notification hub with an access token. `device` is this client's
    /// device id: its own changes come back with it and are skipped.
    pub async fn connect_hub(&self, access: &Secret, device: Uuid) -> Result<Hub, ApiError> {
        let mut url = url::Url::parse(self.url()).map_err(|_| ApiError::BadServerUrl)?;
        let secure = url.scheme() == "https";
        url.set_scheme(if secure { "wss" } else { "ws" }).map_err(|_| ApiError::BadServerUrl)?;
        url.set_path(&format!("{}/notifications/hub", url.path().trim_end_matches('/')));
        url.query_pairs_mut().append_pair("access_token", access.expose());
        let connector = if secure { Some(Connector::Rustls(self.tls_config()?)) } else { Some(Connector::Plain) };
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default().max_message_size(Some(MESSAGE_MAX));
        let connect = tokio_tungstenite::connect_async_tls_with_config(url.as_str(), Some(config), true, connector);
        let (mut stream, _) = tokio::time::timeout(Duration::from_secs(15), connect)
            .await
            .map_err(|_| ApiError::Timeout)?
            .map_err(|_| ApiError::Unreachable)?;
        let hello = format!("{{\"protocol\":\"messagepack\",\"version\":1}}{RECORD_SEPARATOR}");
        stream.send(Message::text(hello)).await.map_err(|_| ApiError::Unreachable)?;
        // The hub answers `{}` and the separator (after any WebSocket pings); an error
        // names the reason.
        let answer = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                match stream.next().await {
                    Some(Ok(Message::Text(t))) => return Ok(t.to_string()),
                    Some(Ok(Message::Binary(b))) => return Ok(String::from_utf8_lossy(&b).into_owned()),
                    Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => continue,
                    _ => return Err(ApiError::Unreachable),
                }
            }
        })
        .await
        .map_err(|_| ApiError::Timeout)??;
        if answer.trim_end_matches(RECORD_SEPARATOR) != "{}" {
            return Err(ApiError::Protocol);
        }
        Ok(Hub { stream, device, pending: VecDeque::new() })
    }

    /// TLS for the hub as for the API: the system's certificates plus the extra ones.
    fn tls_config(&self) -> Result<Arc<rustls::ClientConfig>, ApiError> {
        let mut roots = Vec::new();
        for pem in self.extra_roots() {
            for cert in CertificateDer::pem_slice_iter(pem) {
                roots.push(cert.map_err(|_| ApiError::Certificate)?);
            }
        }
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(roots, provider.clone())
            .map_err(|_| ApiError::Certificate)?;
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| ApiError::Certificate)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Arc::new(config))
    }
}

impl Hub {
    /// The next event; `None` once the connection is closed. Cancelling it while it
    /// waits loses nothing.
    pub async fn next(&mut self) -> Option<Event> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Some(event);
            }
            match tokio::time::timeout(QUIET, self.stream.next()).await {
                Err(_) => {
                    // SignalR ping: [6], length-prefixed.
                    self.stream.send(Message::binary(vec![2u8, 0x91, 6])).await.ok()?;
                    return Some(Event::Idle);
                }
                Ok(None | Some(Err(_))) => return None,
                Ok(Some(Ok(Message::Binary(data)))) => self.pending.extend(decode(&data, self.device)),
                Ok(Some(Ok(Message::Close(_)))) => return None,
                Ok(Some(Ok(_))) => {}
            }
        }
    }
}

/// The events in one binary frame: SignalR messages, each a varint length and a
/// MessagePack array. Invocations of `ReceiveMessage` carry `{ContextId, Type,
/// Payload}`; those from `device` itself are dropped.
pub fn decode(mut data: &[u8], device: Uuid) -> Vec<Event> {
    let mut events = Vec::new();
    let own = device.to_string();
    while !data.is_empty() {
        let Some((length, used)) = varint(data) else { break };
        let Some(body) = data.get(used..used + length) else { break };
        data = &data[used + length..];
        let Ok(Value::Array(message)) = rmpv::decode::read_value(&mut &body[..]) else { continue };
        // [1, headers, invocation id, target, arguments]
        if message.first().and_then(Value::as_i64) != Some(1) || message.get(3).and_then(Value::as_str) != Some("ReceiveMessage")
        {
            continue;
        }
        let Some(Value::Array(arguments)) = message.get(4) else { continue };
        for update in arguments {
            if field(update, "ContextId").and_then(Value::as_str).is_some_and(|c| c.eq_ignore_ascii_case(&own)) {
                continue;
            }
            let Some(kind) = field(update, "Type").and_then(Value::as_i64) else { continue };
            let payload = field(update, "Payload").unwrap_or(&Value::Nil);
            if let Some(event) = event_of(kind, payload) {
                events.push(event);
            }
        }
    }
    events
}

fn field<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.as_map()?.iter().find(|(k, _)| k.as_str().is_some_and(|k| k.eq_ignore_ascii_case(key))).map(|(_, v)| v)
}

/// A SignalR length prefix: 7 bits per byte, low first, at most 5 bytes.
fn varint(data: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for (i, byte) in data.iter().take(5).enumerate() {
        value |= usize::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame as Vaultwarden sends it: one `ReceiveMessage` invocation.
    fn frame(context: Option<&str>, kind: i64, payload: Value) -> Vec<u8> {
        let update = Value::Map(vec![
            ("ContextId".into(), context.map_or(Value::Nil, Value::from)),
            ("Type".into(), kind.into()),
            ("Payload".into(), payload),
        ]);
        let message =
            Value::Array(vec![1.into(), Value::Map(vec![]), Value::Nil, "ReceiveMessage".into(), Value::Array(vec![update])]);
        let mut body = Vec::new();
        rmpv::encode::write_value(&mut body, &message).unwrap();
        let mut out = Vec::new();
        let mut n = body.len();
        loop {
            let byte = (n & 0x7f) as u8;
            n >>= 7;
            out.push(if n > 0 { byte | 0x80 } else { byte });
            if n == 0 {
                break;
            }
        }
        out.extend(body);
        out
    }

    #[test]
    fn decodes_vaultwarden_updates() {
        let me = Uuid::new_v4();
        let payload = Value::Map(vec![("Id".into(), "abc".into())]);
        assert_eq!(decode(&frame(Some("other-device"), 0, payload.clone()), me), vec![Event::Changed]);
        assert_eq!(decode(&frame(None, 5, Value::Nil), me), vec![Event::Changed]);
        assert_eq!(decode(&frame(None, 11, Value::Nil), me), vec![Event::LoggedOut]);
        assert_eq!(decode(&frame(None, 15, payload.clone()), me), vec![Event::AuthRequest("abc".into())]);
        // This device's own change, a Send, and junk: nothing.
        assert!(decode(&frame(Some(&me.to_string()), 0, payload.clone()), me).is_empty());
        assert!(decode(&frame(None, 12, payload), me).is_empty());
        assert!(decode(&[0x05, 1, 2], me).is_empty());
        assert!(decode(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff], me).is_empty());
        // Two messages in one frame.
        let mut two = frame(None, 1, Value::Nil);
        two.extend(frame(None, 11, Value::Nil));
        assert_eq!(decode(&two, me), vec![Event::Changed, Event::LoggedOut]);
        // A long message's length takes two bytes.
        let long = frame(None, 0, Value::Map(vec![("Id".into(), "x".repeat(300).into())]));
        assert_eq!(long[0] & 0x80, 0x80);
        assert_eq!(decode(&long, me), vec![Event::Changed]);
    }
}
