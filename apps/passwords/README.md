# Passwords

A password manager for a self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
server, built with Rust, GTK 4 and the suite's shared theme and widgets. It uses the
Bitwarden client API, so the same account keeps working in the Bitwarden apps, the web
vault and the `bw` command line.

```sh
curl -fsSL https://raw.githubusercontent.com/design-nexus/nixe/main/install.sh | bash -s -- passwords
```

Launch `nixe-passwords`, enter your server's address, email and master password, and
the vault syncs. Two-step login works with an authenticator app or an emailed code.

## What it does

- Lists logins, secure notes, cards, identities and SSH keys by type, folder and
  collection, with favorites, search and a trash with Undo.
- Shows a login's username, password (hidden until shown, hidden again after 30 s),
  current one-time code and web addresses, and every field of cards, identities, SSH
  keys and custom fields, with secret ones hidden until shown.
- Creates and edits logins, secure notes, cards, identities and SSH keys, with a
  password and passphrase generator. SSH keys are generated (Ed25519) or imported
  from an OpenSSH private key file. An edit made in another app in the meantime is caught instead
  of overwritten.
- Honors "ask for master password" on items, and an organization's permissions:
  read-only items and hidden passwords stay that way.
- Creates items in an organization's collections, changes their collections, and
  moves personal items into an organization.
- Nixe Assistant can find logins and copy them ("copy my password for GitHub") once
  you turn that on in Passwords' settings. It asks for a key press each time and never
  sees a password.
- A Security section lists logins with weak, reused or year-old passwords, worked out
  on your computer. On request it checks them against Have I Been Pwned's breach data
  without sending the passwords (only the first five characters of each hash).
- Attachments: saves them to a file you choose, attaches files (up to 100 MB), and
  deletes them. Nothing decrypted goes to a temporary file.
- Works offline from the local copy; edits need the server.
- Can unlock with your desktop keyring instead of the master password, if you turn that
  on. The setting explains what that gives up.

Custom fields can be viewed and copied but not yet edited here, and SSH keys with a
passphrase can't be imported yet.

## How it keeps the vault

- **The daemon:** a small service, `nixe-passwordsd` (systemd unit
  `nixe-passwords.service`), holds the unlocked keys. The window asks it for one
  field at a time over a private socket that only the suite's own programs may use.
- **The local copy:** the server's encrypted data as received, in
  `~/.local/share/nixe-passwords/vault.sqlite` (readable only by you). Nothing
  decrypted is written to disk.
- **The session token:** kept in the desktop keyring (Secret Service).
- **Copying:** the clipboard is marked as holding a password and cleared after 30 s
  (configurable) if it still holds the copy. Clipboard managers that ignore the mark
  can still store it.
- **Locking:** after 15 minutes without use (configurable), when the screen locks,
  before sleep, and with Ctrl+L.

Settings live in `~/.config/nixe-passwords/settings.toml`. Details:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SECURITY.md](docs/SECURITY.md).

| Shortcut | Action |
| --- | --- |
| Ctrl+N | New item |
| Ctrl+F | Search the vault |
| Ctrl+Shift+U / C / O | Copy the username / password / one-time code |
| Ctrl+S | Save in the editor |
| Ctrl+L | Lock the vault |
| F5 | Sync now |
| Ctrl+B | Collapse sidebar |
| Ctrl+, | Settings |
| Esc | Close search or card, or return to the list |
| F1 / ? | Shortcuts |
| Ctrl+Q / Ctrl+W | Close window |

## License

GPL-3.0-only, because it uses Bitwarden's GPL-licensed cryptography library. The rest
of Nixe is MIT.
