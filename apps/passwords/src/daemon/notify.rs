//! Desktop notifications confirming a copy. They name what was copied, never the value.

use std::collections::HashMap;

use tokio::sync::Mutex;
use zbus::zvariant::Value;

const APP_NAME: &str = "Nyx Passwords";
const ICON: &str = "io.github.design_nexus.nyx.Passwords";
const SHOW_MS: i32 = 3500;

#[derive(Default)]
pub struct Notifier {
    bus: Mutex<Option<zbus::Connection>>,
    /// Each notification replaces the last, so copies in a row don't pile up.
    last_id: Mutex<u32>,
}

impl Notifier {
    pub async fn send(&self, summary: &str, body: &str) {
        let mut bus = self.bus.lock().await;
        if bus.is_none() {
            *bus = zbus::Connection::session().await.ok();
        }
        let Some(conn) = bus.as_ref() else { return };
        let mut last = self.last_id.lock().await;
        let hints: HashMap<&str, Value> = HashMap::from([("transient", Value::from(true))]);
        let reply = conn
            .call_method(
                Some("org.freedesktop.Notifications"),
                "/org/freedesktop/Notifications",
                Some("org.freedesktop.Notifications"),
                "Notify",
                &(APP_NAME, *last, ICON, summary, body, Vec::<&str>::new(), hints, SHOW_MS),
            )
            .await;
        match reply.ok().and_then(|m| m.body().deserialize::<u32>().ok()) {
            Some(id) => *last = id,
            // A notification daemon that went away: reconnect next time.
            None => *bus = None,
        }
    }
}
