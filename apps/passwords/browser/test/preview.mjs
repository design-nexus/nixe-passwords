// Pictures of the extension's pages for looking at the design: the popup, the menu under
// a field, the save bar and the passkey window, with made-up items, in Passwords' theme.
// The pages are served as plain local pages with a stand-in for the browser's API, and
// photographed in a headless Firefox (no window is shown).
//
//   cargo run -q -p nyx-passwords --example extension_theme > /tmp/theme.json
//   NYX_PREVIEW_THEME=/tmp/theme.json node apps/passwords/browser/test/preview.mjs OUT_DIR

import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const out = process.argv[2] ?? "preview";
const src = join(dirname(fileURLToPath(import.meta.url)), "../src");
const theme = process.env.NYX_PREVIEW_THEME ? readFileSync(process.env.NYX_PREVIEW_THEME, "utf8") : "null";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
mkdirSync(out, { recursive: true });

// ---- the stand-in API and its made-up vault ----

const mock = `{
const THEME = ${theme};
const params = new URLSearchParams(location.search);
const view = params.get("view") ?? "";
const login = (id, name, username, host, more = {}) => ({ id, name, username, host, kind: "login", has_password: true, has_totp: false, favorite: false, reprompt: false, ...more });
const site = [
  login("gh", "GitHub", "ken@design-nexus.dev", "github.com", { has_totp: true, favorite: true }),
  login("gh2", "GitHub (work)", "kparker-dn", "github.com"),
];
const vault = [
  ...site,
  login("am", "Amazon", "ken@design-nexus.dev", "amazon.com", { favorite: true }),
  login("cf", "Cloudflare", "ops@design-nexus.dev", "cloudflare.com", { has_totp: true }),
  login("di", "Discord", "kenp", "discord.com"),
  login("fi", "Figma", "ken@design-nexus.dev", "figma.com"),
  login("he", "Hetzner Cloud", "ken@design-nexus.dev", "hetzner.com", { has_totp: true }),
  login("ne", "Netflix", "family@parker.house", "netflix.com"),
  login("pr", "Proton Mail", "ken@proton.me", "proton.me"),
  login("st", "Steam", "kenparker", "steampowered.com"),
  { id: "vi", name: "Visa", kind: "card", sub: "Visa •••• 4242", username: "", host: null },
  { id: "id", name: "Home", kind: "identity", sub: "Ken Parker", username: "", host: null },
  { id: "wi", name: "Wi-Fi at home", kind: "note", sub: "", username: "", host: null },
  { id: "ss", name: "Hetzner box", kind: "ssh", sub: "", username: "", host: null },
];
const answers = {
  status: () => ({ state: view.startsWith("state-") ? view.slice(6) : "unlocked" }),
  match: () => ({ host: "github.com", items: site }),
  search: (m) => ({ items: vault.filter((i) => !m.q || i.name.toLowerCase().includes(m.q.toLowerCase()) || (i.sub ?? "").toLowerCase().includes(m.q.toLowerCase())) }),
  security: () => ({ items: [{ id: "gh2", weak: false, reused: true, old: true }] }),
  item: (m) => {
    const i = vault.find((v) => v.id === m.id) ?? {};
    return { ...i, uris: i.host ? [\`https://\${i.host}/login\`, ...(i.id === "gh" ? ["https://gist.github.com"] : [])] : [], has_passkey: i.id === "gh", editable: true, sign_in_with: null };
  },
  totp: () => ({ code: "482913", period: 30, period_left: 12 }),
  generate: (m) => ({ password: m.rules?.kind === "passphrase" ? "Orbit-Velvet-Canyon-Mosaic-Ember7" : "q7#Lm2vX!rT9pW4@zK8n" }),
  username: () => ({ username: "brisk.otter42" }),
  settings: () => ({ fillOnLoad: true, inlineMenu: true, copyTotp: true, rememberSignIn: true, passkeys: false, app: { fill_on_load: true, passkeys: true } }),
  "menu.items": () => ({ state: "unlocked", field: params.get("field") ?? "login", host: "github.com", items: params.get("field") === "card" ? [{ id: "vi", name: "Visa", sub: "Visa •••• 4242" }] : site }),
  "bar.state": () => ({ question: params.get("q") ?? "new", host: "github.com", username: "ken@design-nexus.dev", provider: "google" }),
  "confirm.state": () => ({ ask: params.get("ask") ?? "get", host: "github.com", rpId: "github.com", user: "ken", choices: [{ id: "gh", name: "GitHub", user_name: "ken@design-nexus.dev" }, { id: "gh2", name: "GitHub (work)", user_name: "kparker-dn" }] }),
  pair: () => ({ state: "pending", code: "482913" }),
};
globalThis.browser = {
  runtime: { sendMessage: async (m) => (answers[m.cmd] ?? (() => ({})))(m), id: "preview" },
  storage: { local: { get: async () => ({ theme: THEME, icons: false }), set: async () => {} }, onChanged: { addListener() {} } },
  tabs: { create: async () => {} },
};
addEventListener("load", () => setTimeout(() => {
  const click = (id) => document.getElementById(id)?.click();
  if (view === "generator") click("act-generator");
  if (view === "settings") click("act-settings");
  if (view === "card") { const s = document.getElementById("search"); s.value = "visa"; s.dispatchEvent(new Event("input")); setTimeout(() => document.querySelector(".row")?.click(), 300); }
  if (view === "other") document.querySelector('.row[data-id="gh2"]')?.click();
  if (view === "pending") document.querySelector("button.primary")?.click();
}, 400));
}`;

// A sign-in page with the menu under its field and the save bar, as they sit in a page.
const page = `<!doctype html><html><head><style>
  body { margin: 0; font: 15px system-ui, sans-serif; background: #f6f8fa; color: #1f2328; }
  .box { width: 340px; margin: 70px 0 0 90px; background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 20px; }
  label { display: block; font-weight: 600; margin: 0 0 6px; font-size: 14px; }
  input { width: 100%; box-sizing: border-box; height: 34px; border: 1px solid #0969da; outline: 2px solid #0969da33; border-radius: 6px; padding: 0 10px; font-size: 14px; }
  h1 { font-weight: 300; font-size: 24px; margin: 30px 0 0 90px; }
  .menu { position: absolute; top: 178px; left: 111px; width: 340px; height: 168px; border: 0; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,.3), 0 1px 3px rgba(0,0,0,.2); }
  .bar { position: absolute; top: 12px; right: 12px; width: 400px; height: 152px; border: 0; border-radius: 14px; box-shadow: 0 10px 30px rgba(0,0,0,.3), 0 1px 3px rgba(0,0,0,.2); }
</style></head><body>
  <h1>Sign in to GitHub</h1>
  <div class="box"><label>Username or email address</label><input autofocus></div>
  <iframe class="menu" src="/menu.html?field=login#t"></iframe>
  <iframe class="bar" src="/bar.html?q=new#t"></iframe>
</body></html>`;

const server = http.createServer((req, res) => {
  const path = req.url.split(/[?#]/)[0];
  if (path === "/mock.js") return res.writeHead(200, { "content-type": "text/javascript" }), res.end(mock);
  if (path === "/page") return res.writeHead(200, { "content-type": "text/html" }), res.end(page);
  try {
    let body = readFileSync(join(src, path.replace(/^\/+/, "").replace(/\.\./g, "")), "utf8");
    if (path.endsWith(".html")) body = body.replace('<script src="nyx.js"></script>', '<script src="mock.js"></script><script src="nyx.js"></script>');
    const type = path.endsWith(".css") ? "text/css" : path.endsWith(".js") ? "text/javascript" : "text/html";
    res.writeHead(200, { "content-type": `${type}; charset=utf-8` });
    res.end(body);
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

// ---- Firefox over BiDi ----

const profile = mkdtempSync(join(tmpdir(), "nyx-preview-"));
const port = 9300 + Math.floor(Math.random() * 500);
const firefox = spawn("firefox", ["--headless", "--no-remote", "--profile", profile, "--remote-debugging-port", String(port)], { env: { ...process.env, MOZ_HEADLESS: "1" }, stdio: ["ignore", "ignore", "pipe"] });
await new Promise((r) => firefox.stderr.on("data", (d) => /WebDriver BiDi listening/.test(String(d)) && r()));
const ws = new WebSocket(`ws://127.0.0.1:${port}/session`);
await new Promise((r, e) => ((ws.onopen = r), (ws.onerror = e)));
let nextId = 1;
const pending = new Map();
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.method === "log.entryAdded" && msg.params.level === "error") console.error(`page: ${msg.params.text}`);
  pending.get(msg.id)?.(msg);
};
const bidi = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, (msg) => (msg.error ? reject(new Error(`${method}: ${msg.message}`)) : resolve(msg.result)));
    ws.send(JSON.stringify({ id, method, params }));
  });

await bidi("session.new", { capabilities: {} });
await bidi("session.subscribe", { events: ["log.entryAdded"] });
const { context } = await bidi("browsingContext.create", { type: "tab" });
const shots = [
  ["1-popup-site", "/popup.html", 760, 560],
  ["2-popup-other", "/popup.html?view=other", 760, 560],
  ["3-popup-card", "/popup.html?view=card", 760, 560],
  ["4-popup-generator", "/popup.html?view=generator", 760, 560],
  ["5-popup-settings", "/popup.html?view=settings", 760, 560],
  ["6-popup-locked", "/popup.html?view=state-locked", 760, 560],
  ["7-popup-pairing", "/popup.html?view=state-unpaired", 760, 560],
  ["8-page-menu-and-bar", "/page", 1000, 420],
  ["9-passkey", "/confirm.html?ask=get#t", 420, 460],
];
for (const [name, path, width, height] of shots) {
  await bidi("browsingContext.setViewport", { context, viewport: { width, height } });
  await bidi("browsingContext.navigate", { context, url: base + path, wait: "complete" });
  await sleep(1400);
  const r = await bidi("browsingContext.captureScreenshot", { context });
  writeFileSync(join(out, `${name}.png`), Buffer.from(r.data, "base64"));
}
ws.close();
firefox.kill("SIGTERM");
server.close();
await sleep(500);
rmSync(profile, { recursive: true, force: true });
console.log(`pictures in ${out}`);
