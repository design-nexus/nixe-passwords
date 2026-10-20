//! Attachments: an item's files, each encrypted under a key of its own that the item's
//! key wraps. Files are decrypted only to hand them to the caller, which writes them
//! where the user chose; nothing goes to a temporary file.

use serde_json::Value;
use uuid::Uuid;

use crate::api::{ApiError, MAX_ATTACHMENT, Server};
use crate::secret::{Secret, SecretBytes};
use crate::session::{Result, Session, SessionError};
use crate::store::Store;

/// One attachment as listed: its id, file name and size in bytes. The size is the
/// server's, of the encrypted file: a few dozen bytes more than the file itself.
pub struct Attachment {
    pub id: String,
    pub name: Secret,
    pub size: u64,
}

impl Session {
    /// An item's attachments, names decrypted.
    pub fn attachments(&self, id: Uuid) -> Result<Vec<Attachment>> {
        let c = self.cipher(id)?;
        let mut key = self.keys.item(c.organization_id, c.key.as_deref())?;
        let mut out = Vec::new();
        for a in listed(&c.extra) {
            let Some(attachment) = a["id"].as_str() else { continue };
            let name = key.decrypt_opt(a["fileName"].as_str())?.unwrap_or_else(|| Secret::new("attachment"));
            // The size comes as a string ("123") or a number, depending on the server.
            let size = a["size"].as_str().and_then(|s| s.parse().ok()).or_else(|| a["size"].as_u64()).unwrap_or(0);
            out.push(Attachment { id: attachment.to_string(), name, size });
        }
        Ok(out)
    }

    /// Downloads and decrypts one attachment.
    pub async fn download_attachment(
        &mut self,
        server: &Server,
        refresh: &Secret,
        id: Uuid,
        attachment: &str,
    ) -> Result<SecretBytes> {
        let wrapped = {
            let c = self.cipher(id)?;
            let a = listed(&c.extra).find(|a| a["id"] == attachment).ok_or(SessionError::Api(ApiError::NotFound))?;
            a["key"].as_str().map(str::to_string)
        };
        let access = Secret::new(self.access(server, refresh).await?.expose());
        let data = server.download_attachment(&access, id, attachment).await?;
        let c = self.cipher(id)?;
        let mut key = self.keys.item(c.organization_id, c.key.as_deref())?;
        Ok(key.decrypt_file(wrapped.as_deref(), &data)?)
    }

    /// Encrypts and uploads a file as a new attachment of the item.
    pub async fn add_attachment(
        &mut self,
        store: &mut Store,
        server: &Server,
        refresh: &Secret,
        id: Uuid,
        name: &str,
        data: &[u8],
    ) -> Result<()> {
        if data.len() > MAX_ATTACHMENT {
            return Err(SessionError::NotAllowed("files over 100 MB can't be attached here"));
        }
        let (wrapped, file_name, encrypted) = {
            let c = self.cipher(id)?;
            if !c.can_edit() {
                return Err(SessionError::NotAllowed("this item is read-only for you"));
            }
            let mut key = self.keys.item(c.organization_id, c.key.as_deref())?;
            let (wrapped, encrypted) = key.encrypt_file(data)?;
            (wrapped, key.encrypt(name)?, encrypted)
        };
        let access = Secret::new(self.access(server, refresh).await?.expose());
        server.upload_attachment(&access, id, &wrapped, &file_name, encrypted).await?;
        let latest = server.get_cipher(&access, id).await?;
        self.take(store, latest)
    }

    pub async fn delete_attachment(
        &mut self,
        store: &mut Store,
        server: &Server,
        refresh: &Secret,
        id: Uuid,
        attachment: &str,
    ) -> Result<()> {
        if !self.cipher(id)?.can_edit() {
            return Err(SessionError::NotAllowed("this item is read-only for you"));
        }
        let access = Secret::new(self.access(server, refresh).await?.expose());
        server.delete_attachment(&access, id, attachment).await?;
        let latest = server.get_cipher(&access, id).await?;
        self.take(store, latest)
    }
}

fn listed(extra: &crate::model::Extra) -> impl Iterator<Item = &Value> {
    extra.get("attachments").and_then(Value::as_array).into_iter().flatten()
}
