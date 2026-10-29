//! Emergency access, as Vaultwarden and the official clients have it: trusted contacts
//! who may ask to see this vault and get in once the grantor approves, or after a wait
//! the grantor doesn't stop; and the vaults other accounts trust this one with.
//!
//! Confirming a contact sends them this account's user key, encrypted for their public
//! key, so the grantor first compares the contact's fingerprint phrase with what the
//! contact sees. Viewing opens the grantor's items read-only; taking over an account
//! isn't offered here.

use serde_json::{Value, json};

use crate::api::{ApiError, Server};
use crate::crypto::{Keys, fingerprint_phrase};
use crate::model::Cipher;
use crate::secret::Secret;
use crate::session::{Result, Session, SessionError};
use crate::vault::View;

/// Where a contact stands (Bitwarden's `EmergencyAccessStatusType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Invited,
    Accepted,
    Confirmed,
    RecoveryInitiated,
    RecoveryApproved,
    Other(i64),
}

impl Status {
    fn of(n: i64) -> Status {
        match n {
            0 => Status::Invited,
            1 => Status::Accepted,
            2 => Status::Confirmed,
            3 => Status::RecoveryInitiated,
            4 => Status::RecoveryApproved,
            n => Status::Other(n),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Status::Invited => "invited",
            Status::Accepted => "accepted",
            Status::Confirmed => "confirmed",
            Status::RecoveryInitiated => "requested",
            Status::RecoveryApproved => "approved",
            Status::Other(_) => "other",
        }
    }
}

/// One emergency contact: someone this account trusts (a grantee), or someone who
/// trusts it (a grantor).
#[derive(Debug, Clone)]
pub struct Contact {
    pub id: String,
    /// The other account's id, once it has accepted.
    pub user: Option<String>,
    pub name: String,
    pub email: String,
    /// View only, or take over the account (this client offers viewing only).
    pub takeover: bool,
    pub status: Status,
    pub wait_days: i64,
}

fn contacts(v: &Value, user_key: &str) -> Vec<Contact> {
    let s = |c: &Value, k: &str| c.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    v.get("data")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|c| Contact {
            id: s(c, "id"),
            user: c.get(user_key).and_then(Value::as_str).map(str::to_string),
            name: s(c, "name"),
            email: s(c, "email"),
            takeover: c.get("type").and_then(Value::as_i64) == Some(1),
            status: Status::of(c.get("status").and_then(Value::as_i64).unwrap_or(-1)),
            wait_days: c.get("waitTimeDays").and_then(Value::as_i64).unwrap_or(0),
        })
        .collect()
}

/// A grantor's vault, opened for viewing.
pub struct Grantor {
    pub keys: Keys,
    pub ciphers: Vec<Cipher>,
    pub view: View,
}

/// What the grantor or the contact does with a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The contact asks for access; the wait starts.
    Request,
    /// The grantor lets the contact in now.
    Approve,
    /// The grantor turns the request down.
    Reject,
    /// Either side ends it.
    Remove,
}

impl Server {
    async fn emergency(
        &self,
        access: &Secret,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> crate::api::Result<Value> {
        self.call(access, method, &format!("/api/emergency-access{path}"), body).await
    }
}

impl Session {
    /// The contacts this account trusts, and the accounts that trust it.
    pub async fn emergency_contacts(&mut self, server: &Server, refresh: &Secret) -> Result<(Vec<Contact>, Vec<Contact>)> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let trusted = server.emergency(&access, reqwest::Method::GET, "/trusted", None).await?;
        let granted = server.emergency(&access, reqwest::Method::GET, "/granted", None).await?;
        Ok((contacts(&trusted, "granteeId"), contacts(&granted, "grantorId")))
    }

    /// Invites someone (by their account's email) as an emergency contact.
    pub async fn invite_emergency(&mut self, server: &Server, refresh: &Secret, email: &str, wait_days: u32) -> Result<()> {
        if !(1..=90).contains(&wait_days) {
            return Err(SessionError::NotAllowed("the wait is from 1 to 90 days"));
        }
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let body = json!({"email": email.trim(), "type": 0, "waitTimeDays": wait_days});
        server.emergency(&access, reqwest::Method::POST, "/invite", Some(body)).await?;
        Ok(())
    }

    /// The contact's fingerprint phrase: it must match what they see before confirming.
    pub async fn emergency_fingerprint(&mut self, server: &Server, refresh: &Secret, id: &str) -> Result<String> {
        let (email, public) = self.contact_key(server, refresh, id).await?;
        Ok(fingerprint_phrase(&email, &public)?)
    }

    /// Confirms an accepted contact: they get this account's user key, encrypted for
    /// their public key.
    pub async fn confirm_emergency(&mut self, server: &Server, refresh: &Secret, id: &str) -> Result<()> {
        let (_, public) = self.contact_key(server, refresh, id).await?;
        let key = self.keys.share_user_key(&public)?;
        let access = Secret::new(self.access(server, refresh).await?.expose());
        server.emergency(&access, reqwest::Method::POST, &format!("/{id}/confirm"), Some(json!({"key": key}))).await?;
        Ok(())
    }

    /// A contact's email and public key, from the server.
    async fn contact_key(&mut self, server: &Server, refresh: &Secret, id: &str) -> Result<(String, String)> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let contact = server.emergency(&access, reqwest::Method::GET, &format!("/{id}"), None).await?;
        let user =
            contact.get("granteeId").and_then(Value::as_str).ok_or(SessionError::NotAllowed("they haven't accepted yet"))?;
        let email = contact.get("email").and_then(Value::as_str).unwrap_or_default().to_string();
        let key = server.call(&access, reqwest::Method::GET, &format!("/api/users/{user}/public-key"), None).await?;
        let public = key.get("publicKey").and_then(Value::as_str).ok_or(SessionError::Api(ApiError::Protocol))?;
        Ok((email, public.to_string()))
    }

    pub async fn emergency_step(&mut self, server: &Server, refresh: &Secret, id: &str, step: Step) -> Result<()> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let (method, path) = match step {
            Step::Request => (reqwest::Method::POST, format!("/{id}/initiate")),
            Step::Approve => (reqwest::Method::POST, format!("/{id}/approve")),
            Step::Reject => (reqwest::Method::POST, format!("/{id}/reject")),
            Step::Remove => (reqwest::Method::DELETE, format!("/{id}")),
        };
        server.emergency(&access, method, &path, None).await?;
        Ok(())
    }

    /// Opens a grantor's vault for viewing, once they approved (or the wait ran out).
    pub async fn view_emergency(&mut self, server: &Server, refresh: &Secret, id: &str) -> Result<Grantor> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let v = server.emergency(&access, reqwest::Method::POST, &format!("/{id}/view"), None).await?;
        let shared = v.get("keyEncrypted").and_then(Value::as_str).ok_or(SessionError::Api(ApiError::Protocol))?;
        let keys = self.keys.open_shared(shared, None)?;
        let ciphers: Vec<Cipher> = serde_json::from_value(v.get("ciphers").cloned().unwrap_or_default())
            .map_err(|_| SessionError::Api(ApiError::Protocol))?;
        let view = View::of_ciphers(&keys, &ciphers);
        Ok(Grantor { keys, ciphers, view })
    }

    /// This account's own fingerprint phrase, to read out to someone confirming it.
    pub async fn my_fingerprint(&mut self, server: &Server, refresh: &Secret) -> Result<String> {
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let me = self.snapshot.profile.id;
        let key = server.call(&access, reqwest::Method::GET, &format!("/api/users/{me}/public-key"), None).await?;
        let public = key.get("publicKey").and_then(Value::as_str).ok_or(SessionError::Api(ApiError::Protocol))?;
        Ok(fingerprint_phrase(&self.account.email, public)?)
    }
}
