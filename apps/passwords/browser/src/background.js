// Nyx Passwords for the browser: the link to the Passwords app on this computer
// (docs/NATIVE_MESSAGING.md). The vault stays in the app; this asks it, over the native
// messaging host, for what the page in front needs, one sealed request at a time.
//
// Who may ask for what is decided here, from what the browser says about the sender,
// never from what a page says: content scripts report fields and form submissions; the
// in-page menu, the save bar and the passkey window are this extension's own pages, so
// a page can neither read nor forge them.

const api = globalThis.browser ?? globalThis.chrome;
const HOST = "io.github.design_nexus.nyx.passwords";
const enc = new TextEncoder();
const dec = new TextDecoder();
const own = (page) => api.runtime.getURL(page);

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
const b64url = (bytes) => b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let at = 0;
  for (const p of parts) {
    out.set(new Uint8Array(p), at);
    at += p.byteLength;
  }
  return out;
};
const token = () => b64url(crypto.getRandomValues(new Uint8Array(18)));

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

// ---- this browser's settings ----

const DEFAULTS = { fillOnLoad: true, inlineMenu: true, copyTotp: true, passkeys: false, rememberSignIn: true };

async function prefs() {
  const { prefs: stored } = await api.storage.local.get("prefs");
  return { ...DEFAULTS, ...(stored ?? {}) };
}

// ---- the page ----

async function activeTab() {
  const [tab] = await api.tabs.query({ active: true, currentWindow: true });
  return tab && /^https?:/.test(tab.url ?? "") ? tab : null;
}

const originOf = (url) => {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
};

/// Runs `func` in one frame of a tab; its result.
async function inFrame(tabId, frameId, func, args) {
  const [result] = await api.scripting.executeScript({ target: { tabId, frameIds: [frameId ?? 0] }, func, args });
  return result?.result;
}

// These run in the page. Each fills only if the frame is still the one asked about,
// and only visible fields; a field the user already typed in is left alone on page load.

function fillLogin(origin, username, password, onlyEmpty) {
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
    if (!el || !value || (onlyEmpty && el.value)) return false;
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  };
  const a = set(userField, username);
  const b = set(passwordField, password);
  return a || b;
}

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

// A one-time code: into a code field, or spread over one box per digit.
function fillCode(origin, code) {
  if (location.origin !== origin) return false;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  const set = (el, v) => {
    setter.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const inputs = [...document.querySelectorAll("input")].filter((el) => el.offsetParent !== null && !el.disabled);
  const boxes = inputs.filter((el) => el.maxLength === 1);
  if (boxes.length >= code.length) {
    code.split("").forEach((c, i) => set(boxes[i], c));
    return true;
  }
  const field =
    inputs.find((el) => el.autocomplete === "one-time-code") ??
    inputs.find((el) => /otp|totp|2fa|mfa|one.?time|verification|security.?code|auth.?code|token/i.test(`${el.name} ${el.id} ${el.placeholder}`));
  if (!field) return false;
  set(field, code);
  return true;
}

// A card or identity, by the fields' autocomplete tokens, else their names.
function fillForm(origin, kind, values) {
  if (location.origin !== origin) return 0;
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
  const map =
    kind === "card"
      ? [
          ["cc-name", /card.?holder|name.?on.?card|cc.?name/i, values.cardholderName],
          ["cc-number", /card.?number|cc.?num|cardnum/i, values.number],
          ["cc-exp-month", /exp.*month|month/i, values.expMonth],
          ["cc-exp-year", /exp.*year|year/i, values.expYear],
          ["cc-exp", /expir|exp.?date|mm.?yy/i, values.expMonth && values.expYear ? `${values.expMonth.padStart(2, "0")}/${values.expYear.slice(-2)}` : ""],
          ["cc-csc", /cvc|cvv|csc|security.?code/i, values.code],
        ]
      : [
          ["given-name", /first.?name|given/i, values.firstName],
          ["additional-name", /middle/i, values.middleName],
          ["family-name", /last.?name|surname|family/i, values.lastName],
          ["email", /e.?mail/i, values.email],
          ["tel", /phone|tel/i, values.phone],
          ["organization", /company|organi[sz]ation/i, values.company],
          ["address-line1", /address.?1|street|address$/i, values.address1],
          ["address-line2", /address.?2/i, values.address2],
          ["address-level2", /city|town/i, values.city],
          ["address-level1", /state|province|region/i, values.state],
          ["postal-code", /zip|postal|postcode/i, values.postalCode],
          ["country", /country/i, values.country],
          ["username", /user.?name/i, values.username],
        ];
  const inputs = [...document.querySelectorAll("input, select")].filter((el) => el.offsetParent !== null && !el.disabled);
  let n = 0;
  for (const [token, pattern, value] of map) {
    if (!value) continue;
    const el =
      inputs.find((i) => (i.autocomplete || "").split(" ").includes(token)) ??
      inputs.find((i) => !i.autocomplete && pattern.test(`${i.name} ${i.id} ${i.placeholder ?? ""} ${i.getAttribute("aria-label") ?? ""}`));
    if (!el || el.value) continue;
    if (el.tagName === "SELECT") {
      const option = [...el.options].find((o) => o.value === value || o.text.trim() === value || o.value === value.padStart(2, "0"));
      if (!option) continue;
      el.value = option.value;
    } else {
      setter.call(el, value);
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }
    el.dispatchEvent(new Event("change", { bubbles: true }));
    n++;
  }
  return n;
}

// Universal sign-on: clicks the page's "Sign in with <provider>" button.
function clickProvider(origin, provider) {
  if (location.origin !== origin) return false;
  const words = { google: /google/i, apple: /apple/i, microsoft: /microsoft|outlook|live\.com/i, github: /github/i, facebook: /facebook|meta/i, gitlab: /gitlab/i, twitter: /twitter|\bx\b/i, linkedin: /linkedin/i, amazon: /amazon/i, slack: /slack/i }[provider];
  if (!words) return false;
  const candidates = [...document.querySelectorAll("a, button, [role=button], input[type=submit]")].filter((el) => el.offsetParent !== null);
  const el = candidates.find((c) => {
    const text = `${c.textContent} ${c.getAttribute("aria-label") ?? ""} ${c.getAttribute("title") ?? ""} ${c.value ?? ""} ${c.href ?? ""}`;
    return words.test(text) && /sign|log|continue|with|auth|oauth/i.test(text);
  });
  if (!el) return false;
  el.click();
  return true;
}

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

// ---- filling ----

/// Fills a login into a frame of a tab: the app checks the item belongs to the page (or
/// was confirmed for it) and the frame's site.
async function fill(tab, id, { frameId = 0, frameUrl, confirmed = false, trigger } = {}) {
  const frame = frameUrl ?? tab.url;
  const answer = await request({ r: "fill", url: tab.url, id, frame, confirmed, trigger });
  if (answer.error || answer.state) return answer;
  const done = await inFrame(tab.id, frameId, fillLogin, [originOf(frame), answer.username, answer.password, trigger === "load"]);
  if (!done) return { error: "NoForm" };
  rememberUsed(tab.id, answer.id);
  if (answer.has_totp && trigger !== "load" && (await prefs()).copyTotp) {
    request({ r: "copy", id: answer.id, field: "totp" }).catch(() => {});
  }
  return { filled: true, id: answer.id };
}

const lastUsed = new Map();
function rememberUsed(tabId, id) {
  lastUsed.set(tabId, id);
}

async function save() {
  const tab = await activeTab();
  if (!tab) return { error: "NoUrl" };
  const form = await inFrame(tab.id, 0, readForm, [originOf(tab.url)]);
  if (!form?.password) return { error: "NoPassword" };
  return request({ r: "save", url: tab.url, username: form.username, password: form.password });
}

// ---- the in-page menu, the save bar and the passkey window ----

// Each is opened for one frame of one tab, under a random token; it may act only for
// that frame, and only while the token lives.
const opened = new Map();

function open(kind, data) {
  const t = token();
  opened.set(t, { kind, at: Date.now(), ...data });
  setTimeout(() => opened.delete(t), 10 * 60 * 1000);
  return t;
}

function owned(message, sender, page) {
  const entry = opened.get(message.token);
  if (!entry || !sender.url?.startsWith(own(page))) return null;
  // A page's own frames can't open these; they come from this extension.
  if (entry.tabId !== undefined && sender.tab && sender.tab.id !== entry.tabId) return null;
  return entry;
}

async function menuItems(entry) {
  const tab = await api.tabs.get(entry.tabId).catch(() => null);
  if (!tab) return { state: "gone" };
  const status = await request({ r: "status" });
  if (status.state !== "unlocked") return { state: status.state ?? "unknown" };
  if (entry.field === "card" || entry.field === "identity") {
    const found = await request({ r: entry.field === "card" ? "cards" : "identities", url: tab.url });
    return { state: "unlocked", field: entry.field, items: found.items ?? [] };
  }
  const found = await request({ r: "match", url: tab.url });
  return { state: "unlocked", field: entry.field, host: new URL(tab.url).host, items: found.items ?? [] };
}

async function menuAct(entry, message) {
  const tab = await api.tabs.get(entry.tabId);
  const target = { frameId: entry.frameId, frameUrl: entry.frameUrl };
  switch (message.cmd) {
    case "menu.fill":
      return fill(tab, message.id, target);
    case "menu.code": {
      const answer = await request({ r: "totp", url: tab.url, id: message.id, frame: entry.frameUrl });
      if (!answer.code) return answer;
      return { filled: await inFrame(tab.id, entry.frameId, fillCode, [originOf(entry.frameUrl), answer.code]) };
    }
    case "menu.form": {
      const answer = await request({ r: entry.field === "card" ? "fill_card" : "fill_identity", url: tab.url, id: message.id, frame: entry.frameUrl });
      if (answer.error) return answer;
      return { filled: await inFrame(tab.id, entry.frameId, fillForm, [originOf(entry.frameUrl), entry.field, answer]) };
    }
    case "menu.generate": {
      const answer = await request({ r: "generate" });
      if (!answer.password) return answer;
      return { filled: await inFrame(tab.id, entry.frameId, fillNew, [originOf(entry.frameUrl), answer.password]) };
    }
    case "menu.signin":
      return { clicked: await inFrame(tab.id, entry.frameId, clickProvider, [originOf(entry.frameUrl), message.provider]) };
    case "menu.unlock":
      return request({ r: "unlock" });
    default:
      return { error: "unknown" };
  }
}

// Saving: a submitted form's login waits here (in memory, two minutes at most) while
// the bar asks.
async function offerSave(tab, frameUrl, form) {
  if (!form.password) return;
  const answer = await request({ r: "check", url: frameUrl, username: form.username, password: form.password });
  if (answer.state !== "new" && answer.state !== "changed") return;
  const t = open("bar", {
    tabId: tab.id,
    frameUrl,
    username: form.username,
    password: form.password,
    question: answer.state,
    host: new URL(frameUrl).host,
  });
  setTimeout(() => {
    const e = opened.get(t);
    if (e) e.password = "";
  }, 2 * 60 * 1000);
  showBar(tab.id, t);
}

async function showBar(tabId, t) {
  // After a sign-in the page usually navigates: try now, and again once it's loaded.
  const send = () => api.tabs.sendMessage(tabId, { cmd: "bar", token: t }, { frameId: 0 }).catch(() => {});
  send();
  pendingBars.set(tabId, t);
}
const pendingBars = new Map();

async function barAnswer(entry, choice) {
  switch (choice) {
    case "save":
      return request({ r: "save", url: entry.frameUrl, username: entry.username, password: entry.password });
    case "never":
      return request({ r: "exclude", url: entry.frameUrl });
    case "remember":
      return request({ r: "signin.save", url: entry.frameUrl, provider: entry.provider, username: "" });
    default:
      return {};
  }
}

// Universal sign-on: a click on a "Sign in with …" button, then the tab comes back to the
// site; then the bar offers to remember it.
const providerClicks = new Map();

async function backFromProvider(tabId, url) {
  const click = providerClicks.get(tabId);
  if (!click || Date.now() - click.at > 5 * 60 * 1000 || originOf(url) !== click.origin) return;
  providerClicks.delete(tabId);
  if (!(await prefs()).rememberSignIn) return;
  const found = await request({ r: "match", url });
  if ((found.items ?? []).some((i) => i.sign_in_with === click.provider)) return;
  const t = open("bar", { tabId, frameUrl: url, question: "provider", provider: click.provider, host: new URL(url).host });
  showBar(tabId, t);
}

// ---- passkeys ----

// The page asked for a passkey (through the content script, which only relays). The
// client data is built here, with the frame's origin as the browser reports it; the
// user picks or confirms in this extension's own window; the app signs.
async function passkey(kind, options, sender) {
  const settings = await request({ r: "settings" });
  if (!settings.passkeys || !(await prefs()).passkeys) return { fallback: true };
  const origin = originOf(sender.url);
  const page = new URL(sender.url);
  const rpId = (kind === "create" ? options.rp?.id : options.rpId) ?? page.hostname;
  const clientData = JSON.stringify({
    type: kind === "create" ? "webauthn.create" : "webauthn.get",
    challenge: options.challenge,
    origin,
    crossOrigin: sender.frameId !== 0,
  });
  const hash = b64url(await crypto.subtle.digest("SHA-256", enc.encode(clientData)));
  let choices = [];
  if (kind === "get") {
    const found = await request({ r: "passkey.list", url: sender.url, rp_id: rpId, allow: (options.allowCredentials ?? []).map((c) => c.id) });
    if (found.error) return { fallback: true };
    choices = found.items ?? [];
    if (!choices.length) return { fallback: true };
  } else {
    const found = await request({ r: "match", url: sender.url });
    choices = (found.items ?? []).map((i) => ({ id: i.id, name: i.name, user_name: i.username }));
  }
  const choice = await confirmInWindow({ ask: kind, host: page.host, rpId, user: options.user?.name ?? "", choices });
  if (!choice) return { fallback: choice === null };
  if (kind === "get") {
    const picked = choices[choice.index];
    const a = await request({ r: "passkey.get", url: sender.url, rp_id: rpId, id: picked.id, credential_id: picked.credential_id, client_data_hash: hash, confirmed: true });
    if (a.error) return { error: a.error };
    return { credential: { id: a.credential_id, clientDataJSON: b64url(enc.encode(clientData)), authenticatorData: a.authenticator_data, signature: a.signature, userHandle: a.user_handle } };
  }
  const made = await request({
    r: "passkey.create",
    url: sender.url,
    rp_id: rpId,
    rp_name: options.rp?.name ?? rpId,
    user_id: options.user?.id,
    user_name: options.user?.name ?? "",
    user_display_name: options.user?.displayName ?? "",
    client_data_hash: hash,
    exclude: (options.excludeCredentials ?? []).map((c) => c.id),
    rk: options.authenticatorSelection?.residentKey !== "discouraged",
    into: choice.into ?? null,
    confirmed: true,
  });
  if (made.error) return { error: made.error };
  return {
    credential: {
      id: made.credential_id,
      clientDataJSON: b64url(enc.encode(clientData)),
      attestationObject: made.attestation_object,
      authenticatorData: made.authenticator_data,
      publicKey: made.public_key,
      algorithm: made.algorithm,
    },
  };
}

// The user's confirmation in a small window of this extension's own: a page can't draw
// it. `null` means "use the browser's own instead"; `false`, declined.
function confirmInWindow(data) {
  return new Promise((resolve) => {
    const t = open("confirm", { ...data, resolve });
    api.windows.create({ url: own(`confirm.html#${t}`), type: "popup", width: 420, height: 460 }).then((w) => {
      const gone = (id) => {
        if (id !== w.id) return;
        api.windows.onRemoved.removeListener(gone);
        const e = opened.get(t);
        if (e) {
          opened.delete(t);
          resolve(false);
        }
      };
      api.windows.onRemoved.addListener(gone);
    });
  });
}

let passkeyScript = false;
async function syncPasskeyScript() {
  const on = (await prefs()).passkeys;
  try {
    if (on && !passkeyScript) {
      await api.scripting.registerContentScripts([
        { id: "nyx-webauthn", matches: ["https://*/*", "http://localhost/*"], js: ["page.js"], runAt: "document_start", allFrames: true, world: "MAIN" },
      ]);
      passkeyScript = true;
    } else if (!on && passkeyScript) {
      await api.scripting.unregisterContentScripts({ ids: ["nyx-webauthn"] });
      passkeyScript = false;
    }
  } catch {
    passkeyScript = on;
  }
}
syncPasskeyScript();

// ---- the badge, the active site for Glimpse ----

let reported = { url: "", at: 0 };

async function reportActive(force = false) {
  const tab = await activeTab().catch(() => null);
  if (!tab) return;
  if (!force && tab.url === reported.url && Date.now() - reported.at < 5000) return;
  reported = { url: tab.url, at: Date.now() };
  const { pairing } = await api.storage.local.get("pairing");
  if (!pairing) return;
  request({ r: "context", url: tab.url }).catch(() => {});
  const found = await request({ r: "match", url: tab.url }).catch(() => ({}));
  const n = found.items?.length ?? 0;
  api.action.setBadgeText({ tabId: tab.id, text: n ? String(n) : "" });
  api.action.setBadgeBackgroundColor?.({ color: "#7aa2f7" });
}

api.tabs.onActivated.addListener(() => reportActive());
api.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (tab.active && (change.url || change.status === "complete")) reportActive();
  if (change.status === "complete" && tab.url) {
    backFromProvider(tabId, tab.url);
    const t = pendingBars.get(tabId);
    if (t && opened.has(t)) api.tabs.sendMessage(tabId, { cmd: "bar", token: t }, { frameId: 0 }).catch(() => {});
    pendingBars.delete(tabId);
  }
});
api.tabs.onRemoved.addListener((tabId) => {
  lastUsed.delete(tabId);
  providerClicks.delete(tabId);
  pendingBars.delete(tabId);
});
api.windows.onFocusChanged.addListener((w) => {
  if (w !== api.windows.WINDOW_ID_NONE) reportActive();
});
// Also now and then: a vault unlocked after the page loaded hears about it this way.
api.alarms.create("report", { periodInMinutes: 0.5 });
api.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "report") reportActive(true);
});

// ---- messages ----

/// Passwords' theme (and whether it shows site icons), kept for this extension's pages
/// so they open in the right colours before asking.
async function refreshTheme() {
  const s = await request({ r: "settings" }).catch(() => ({}));
  if (s.theme) await api.storage.local.set({ theme: s.theme, icons: Boolean(s.icons) });
  return s;
}

/// From the popup: anything about the vault, for the tab in front.
async function fromPopup(message) {
  const tab = await activeTab();
  switch (message.cmd) {
    case "status": {
      const { pairing } = await api.storage.local.get("pairing");
      if (!pairing) return { state: "unpaired" };
      const status = await request({ r: "status" });
      if (status.state === "unlocked") reportActive(true);
      if (status.state) refreshTheme();
      return status.state ? status : { state: "unknown" };
    }
    case "pair":
      return pair();
    case "unpair":
      await api.storage.local.remove("pairing");
      return { state: "unpaired" };
    case "match": {
      if (!tab) return { items: [], host: "" };
      const answer = await request({ r: "match", url: tab.url });
      return { ...answer, host: new URL(tab.url).host };
    }
    case "search":
      return request({ r: "search", q: message.q ?? "" });
    case "item":
      return request({ r: "item", id: message.id });
    case "security":
      return request({ r: "security", ids: message.ids ?? [] });
    case "fill":
      if (!tab) return { error: "NoUrl" };
      return fill(tab, message.id, { confirmed: Boolean(message.confirmed) });
    case "add_uri":
      if (!tab) return { error: "NoUrl" };
      return request({ r: "add_uri", url: tab.url, id: message.id });
    case "copy":
      return request({ r: "copy", id: message.id, field: message.field });
    case "totp":
      if (!tab) return { error: "NoUrl" };
      return request({ r: "totp", url: tab.url, id: message.id });
    case "generate": {
      const answer = await request({ r: "generate", rules: message.rules });
      if (!answer.password || !message.into || !tab) return answer;
      return { ...answer, filled: await inFrame(tab.id, 0, fillNew, [originOf(tab.url), answer.password]) };
    }
    case "username":
      return request({ r: "username", url: tab?.url ?? "" });
    case "unlock":
      return request({ r: "unlock" });
    case "save":
      return save();
    case "settings":
      return { ...(await prefs()), app: await refreshTheme() };
    case "lock":
      return request({ r: "lock" });
    case "fill_generated": {
      const value = String(message.value ?? "");
      if (!tab || !value || value.length > 256) return { error: "NoForm" };
      return { filled: await inFrame(tab.id, 0, fillNew, [originOf(tab.url), value]) };
    }
    case "signin":
      if (!tab) return { error: "NoUrl" };
      return { clicked: await inFrame(tab.id, 0, clickProvider, [originOf(tab.url), String(message.provider ?? "")]) };
    case "fill_item": {
      if (!tab) return { error: "NoUrl" };
      const kind = message.kind === "card" ? "card" : "identity";
      const answer = await request({ r: kind === "card" ? "fill_card" : "fill_identity", url: tab.url, id: message.id, frame: tab.url });
      if (answer.error) return answer;
      const filled = await inFrame(tab.id, 0, fillForm, [originOf(tab.url), kind, answer]);
      return filled ? { filled } : { error: "NoForm" };
    }
    case "set": {
      const current = await prefs();
      await api.storage.local.set({ prefs: { ...current, [message.key]: Boolean(message.value) } });
      if (message.key === "passkeys") syncPasskeyScript();
      return prefs();
    }
    default:
      return { error: "unknown" };
  }
}

/// From a content script, about the frame it runs in (the browser says which).
async function fromPage(message, sender) {
  const tab = sender.tab;
  const frameUrl = sender.url;
  if (!/^https?:/.test(frameUrl ?? "")) return null;
  const { pairing } = await api.storage.local.get("pairing");
  if (!pairing) return null;
  switch (message.cmd) {
    case "field": {
      if (!(await prefs()).inlineMenu) return null;
      const field = ["login", "new-password", "otp", "card", "identity"].includes(message.field) ? message.field : "login";
      return { token: open("menu", { tabId: tab.id, frameId: sender.frameId, frameUrl, field }) };
    }
    case "loaded": {
      if (!(await prefs()).fillOnLoad) return null;
      return fill(tab, null, { frameId: sender.frameId, frameUrl, trigger: "load" });
    }
    case "submitted":
      offerSave(tab, frameUrl, { username: String(message.username ?? "").slice(0, 512), password: String(message.password ?? "").slice(0, 1024) });
      return {};
    case "provider":
      providerClicks.set(tab.id, { provider: String(message.provider), origin: originOf(tab.url), at: Date.now() });
      return {};
    case "passkey":
      return passkey(message.kind === "create" ? "create" : "get", message.options ?? {}, sender);
    default:
      return null;
  }
}

api.runtime.onMessage.addListener((message, sender, reply) => {
  // Only this extension's own scripts and pages, never another extension.
  if (sender.id !== api.runtime.id) return false;
  let answer;
  const cmd = String(message.cmd ?? "");
  if (cmd.startsWith("menu.")) {
    const entry = owned(message, sender, "menu.html");
    if (!entry || entry.kind !== "menu") return false;
    answer = cmd === "menu.items" ? menuItems(entry) : menuAct(entry, message);
  } else if (cmd.startsWith("bar.")) {
    const entry = owned(message, sender, "bar.html");
    if (!entry || entry.kind !== "bar") return false;
    if (cmd === "bar.state") {
      answer = Promise.resolve({ question: entry.question, host: entry.host, username: entry.username, provider: entry.provider });
    } else {
      opened.delete(message.token);
      answer = barAnswer(entry, message.choice);
    }
  } else if (cmd.startsWith("confirm.")) {
    const entry = owned(message, sender, "confirm.html");
    if (!entry || entry.kind !== "confirm") return false;
    if (cmd === "confirm.state") {
      answer = Promise.resolve({ ask: entry.ask, host: entry.host, rpId: entry.rpId, user: entry.user, choices: entry.choices });
    } else {
      opened.delete(message.token);
      // `null` is "the browser's own", kept apart from a refusal.
      entry.resolve(message.choice === undefined ? false : message.choice);
      answer = Promise.resolve({});
    }
  } else if (cmd === "icon" && sender.url?.startsWith(own(""))) {
    answer = request({ r: "icon", host: String(message.host ?? "") });
  } else if (sender.url?.startsWith(own("popup.html"))) {
    // The popup (or the same page opened in a tab: pages can't load it, it isn't
    // web-accessible).
    answer = fromPopup(message);
  } else if (sender.tab && !sender.url?.startsWith(own(""))) {
    answer = fromPage(message, sender);
  } else {
    return false;
  }
  answer.then(reply, (e) => reply({ error: String(e) }));
  return true;
});

// ---- the shortcut and the context menu ----

let cycle = { tabId: null, at: 0, index: 0 };

async function fillShortcut() {
  const tab = await activeTab();
  if (!tab) return;
  const found = await request({ r: "match", url: tab.url });
  const items = (found.items ?? []).filter((i) => i.has_password || i.username);
  if (!items.length) {
    api.action.openPopup?.().catch(() => {});
    return;
  }
  // Pressed again soon: the next login.
  cycle = cycle.tabId === tab.id && Date.now() - cycle.at < 10000 ? { ...cycle, index: cycle.index + 1 } : { tabId: tab.id, index: 0 };
  cycle.at = Date.now();
  await fill(tab, items[cycle.index % items.length].id);
}

api.commands.onCommand.addListener(async (command) => {
  if (command === "fill-login") return fillShortcut();
  if (command === "generate-password") {
    const tab = await activeTab();
    const answer = await request({ r: "generate" });
    if (tab && answer.password) inFrame(tab.id, 0, fillNew, [originOf(tab.url), answer.password]);
  }
});

api.runtime.onInstalled.addListener((details) => {
  // First install: a tab to pair this browser with Passwords.
  if (details.reason === "install") api.tabs.create({ url: own("popup.html#welcome") });
  api.contextMenus.removeAll(() => {
    api.contextMenus.create({ id: "nyx-fill", title: "Fill the login for this page", contexts: ["editable", "page"] });
    api.contextMenus.create({ id: "nyx-generate", title: "Generate a password here", contexts: ["editable"] });
  });
});
api.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab || !/^https?:/.test(tab.url ?? "")) return;
  if (info.menuItemId === "nyx-fill") fillShortcut();
  if (info.menuItemId === "nyx-generate") {
    const answer = await request({ r: "generate" });
    if (answer.password) inFrame(tab.id, info.frameId ?? 0, fillNew, [originOf(info.frameUrl ?? tab.url), answer.password]);
  }
});
