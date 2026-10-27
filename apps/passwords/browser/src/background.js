// Nyx Passwords for the browser: the link to the Passwords app on this computer
// (docs/NATIVE_MESSAGING.md). The vault stays in the app; this asks it, over the
// native messaging host, for the logins of the page in front, one at a time.
//
// After pairing, every request is sealed (AES-256-GCM) with a key only this extension
// and the app know, so the host in between can't read or forge them.

const api = globalThis.browser ?? globalThis.chrome;
const HOST = "io.github.design_nexus.nyx.passwords";
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---- the native host ----

let port = null;
const waiting = [];

function native(frame) {
  return new Promise((resolve) => {
    if (!port) {
      try {
        port = api.runtime.connectNative(HOST);
      } catch {
        resolve({ t: "unavailable" });
        return;
      }
      port.onMessage.addListener((reply) => waiting.shift()?.(reply));
      port.onDisconnect.addListener(() => {
        port = null;
        // Not installed, or the host stopped: everyone waiting hears so.
        while (waiting.length) waiting.shift()({ t: "unavailable" });
      });
    }
    waiting.push(resolve);
    port.postMessage(frame);
  });
}

// ---- bytes ----

const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (text) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let at = 0;
  for (const p of parts) {
    out.set(new Uint8Array(p), at);
    at += p.byteLength;
  }
  return out;
};

// ---- pairing ----

// X25519 with the app's key; HKDF-SHA256 (salt: our key then the app's) gives the
// pairing key and the six-digit code both sides show.
async function pair() {
  const mine = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pub = new Uint8Array(await crypto.subtle.exportKey("raw", mine.publicKey));
  const reply = await native({ t: "hello", v: 1, pub: b64(pub) });
  if (reply.t !== "pairing") return { state: reply.t, error: reply.error };
  const theirs = unb64(reply.pub);
  const peer = await crypto.subtle.importKey("raw", theirs, { name: "X25519" }, false, []);
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: peer }, mine.privateKey, 256);
  const ikm = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const salt = concat(pub, theirs);
  const derive = (info, bits) =>
    crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode(info) }, ikm, bits);
  // Protocol labels from before the rename; the daemon uses the same ones.
  const key = await derive("nixe-passwords pair v1", 256);
  const code = String(new DataView(await derive("nixe-passwords code v1", 32)).getUint32(0) % 1000000).padStart(6, "0");
  await api.storage.local.set({ pairing: { id: reply.p, key: b64(key) } });
  return { state: "pending", code };
}

// ---- sealed requests ----

let last = 0;

async function request(body) {
  const { pairing } = await api.storage.local.get("pairing");
  if (!pairing) return { state: "unpaired" };
  const key = await crypto.subtle.importKey("raw", unb64(pairing.key), "AES-GCM", false, ["encrypt", "decrypt"]);
  // Counters only go up, and stay near the clock: the app refuses anything else.
  const n = Math.max(Date.now(), last + 1);
  last = n;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: enc.encode(`${pairing.id}|${n}`) },
    key,
    enc.encode(JSON.stringify(body)),
  );
  const reply = await native({ t: "msg", p: pairing.id, n, c: b64(concat(iv, sealed)) });
  if (reply.t !== "msg") {
    if (reply.t === "unknown") await api.storage.local.remove("pairing");
    return { state: reply.t === "unknown" ? "unpaired" : reply.t, error: reply.error };
  }
  const opened = unb64(reply.c);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: opened.slice(0, 12), additionalData: enc.encode(`${pairing.id}|${n}|r`) },
    key,
    opened.slice(12),
  );
  return JSON.parse(dec.decode(plain));
}

// ---- the page ----

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab && /^https?:/.test(tab.url ?? "") ? tab : null;
}

// Runs in the page. Fills only if the page is still the one the login was for.
function fillPage(origin, username, password) {
  if (location.origin !== origin) return false;
  const visible = (el) => el.offsetParent !== null && !el.disabled && !el.readOnly;
  const fields = [...document.querySelectorAll("input")].filter(visible);
  const passwordField = fields.find((el) => el.type === "password");
  // The username is the nearest field before the password one (or the only form field).
  const nearestFirst = (passwordField ? fields.slice(0, fields.indexOf(passwordField)) : fields).reverse();
  const userField =
    nearestFirst.find((el) => /username|email/.test(el.autocomplete)) ??
    nearestFirst.find((el) => ["text", "email", "tel"].includes(el.type));
  const set = (el, value) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  if (userField && username) set(userField, username);
  if (passwordField && password) set(passwordField, password);
  return Boolean(userField || passwordField);
}

// Puts a generated password into the page's empty password fields (a sign-up form).
function fillNew(origin, password) {
  if (location.origin !== origin) return 0;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  let n = 0;
  for (const el of document.querySelectorAll('input[type="password"]')) {
    if (el.offsetParent === null || el.value) continue;
    setter.call(el, password);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    n++;
  }
  return n;
}

// Runs in the page: the login just typed into it, if it's still the page asked about.
function readForm(origin) {
  if (location.origin !== origin) return null;
  const fields = [...document.querySelectorAll("input")].filter((el) => el.offsetParent !== null);
  const passwordField = fields.find((el) => el.type === "password" && el.value);
  if (!passwordField) return null;
  const nearestFirst = fields.slice(0, fields.indexOf(passwordField)).reverse();
  const userField =
    nearestFirst.find((el) => /username|email/.test(el.autocomplete) && el.value) ??
    nearestFirst.find((el) => ["text", "email", "tel"].includes(el.type) && el.value);
  return { username: userField?.value ?? "", password: passwordField.value };
}

// Saves what's typed in the page's login form (the user asked, from the popup). The
// password goes from the page to the app; the popup only hears what happened.
async function save() {
  const tab = await activeTab();
  if (!tab) return { error: "NoUrl" };
  const [result] = await api.scripting.executeScript({
    target: { tabId: tab.id },
    func: readForm,
    args: [new URL(tab.url).origin],
  });
  const form = result?.result;
  if (!form?.password) return { error: "NoPassword" };
  return request({ r: "save", url: tab.url, username: form.username, password: form.password });
}

async function fill(id) {
  const tab = await activeTab();
  if (!tab) return { error: "NoUrl" };
  const answer = await request({ r: "fill", url: tab.url, id, frame: tab.url });
  if (answer.error || answer.state) return answer;
  const [result] = await api.scripting.executeScript({
    target: { tabId: tab.id },
    func: fillPage,
    args: [new URL(tab.url).origin, answer.username, answer.password],
  });
  return result?.result ? { filled: true } : { error: "NoForm" };
}

// ---- the active site, for Glimpse's "pw" ----

let reported = { url: "", at: 0 };

async function reportActive(force = false) {
  const tab = await activeTab().catch(() => null);
  if (!tab) return;
  if (!force && tab.url === reported.url && Date.now() - reported.at < 5000) return;
  reported = { url: tab.url, at: Date.now() };
  const { pairing } = await api.storage.local.get("pairing");
  if (pairing) request({ r: "context", url: tab.url }).catch(() => {});
}

api.tabs.onActivated.addListener(reportActive);
api.tabs.onUpdated.addListener((_, change, tab) => {
  if (tab.active && (change.url || change.status === "complete")) reportActive();
});
api.windows.onFocusChanged.addListener((w) => {
  if (w !== api.windows.WINDOW_ID_NONE) reportActive();
});
// Also now and then: a vault unlocked after the page loaded hears about it this way.
api.alarms.create("report", { periodInMinutes: 0.5 });
api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "report") reportActive(true);
});

// ---- the popup and the shortcut ----

async function handle(message) {
  switch (message.cmd) {
    case "status": {
      const { pairing } = await api.storage.local.get("pairing");
      if (!pairing) return { state: "unpaired" };
      const status = await request({ r: "status" });
      if (status.state === "unlocked") reportActive(true);
      return status.state ? status : { state: "unknown" };
    }
    case "pair":
      return pair();
    case "unpair":
      await api.storage.local.remove("pairing");
      return { state: "unpaired" };
    case "match": {
      const tab = await activeTab();
      if (!tab) return { items: [], host: "" };
      const answer = await request({ r: "match", url: tab.url });
      return { ...answer, host: new URL(tab.url).host };
    }
    case "fill":
      return fill(message.id);
    case "totp": {
      const tab = await activeTab();
      return tab ? request({ r: "totp", url: tab.url, id: message.id }) : { error: "NoUrl" };
    }
    case "generate": {
      const tab = await activeTab();
      if (!tab) return { error: "NoUrl" };
      const answer = await request({ r: "generate" });
      if (!answer.password) return answer;
      const [result] = await api.scripting.executeScript({
        target: { tabId: tab.id },
        func: fillNew,
        args: [new URL(tab.url).origin, answer.password],
      });
      return { filled: result?.result ?? 0 };
    }
    case "unlock":
      return request({ r: "unlock" });
    case "save":
      return save();
    default:
      return { error: "unknown" };
  }
}

api.runtime.onMessage.addListener((message, sender, reply) => {
  // Only this extension's own pages: never a web page or another extension.
  if (sender.id !== api.runtime.id || sender.tab) return false;
  handle(message).then(reply, (e) => reply({ error: String(e) }));
  return true;
});

api.commands.onCommand.addListener(async (command) => {
  if (command !== "fill-login") return;
  const found = await handle({ cmd: "match" });
  if (found.items?.length === 1) {
    await fill(found.items[0].id);
  } else {
    api.action.openPopup?.().catch(() => {});
  }
});
