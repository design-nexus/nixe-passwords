// The popup: search the vault, the page's logins first, the chosen item with Autofill
// and copy, the generator and this browser's settings. It never sees a password:
// filling goes from the background script straight into the page, and copies go
// through Passwords' clipboard, which clears itself.

const { api, el, icon, tile } = NYX;
const ask = (message) => api.runtime.sendMessage(message);
const $ = (id) => document.getElementById(id);
const header = $("header");
const list = $("list");
const detail = $("detail");
const panes = $("panes");
const stateView = $("state");
const search = $("search");

const KINDS = { login: "Login", card: "Card", identity: "Identity", note: "Secure note", ssh: "SSH key", other: "Item" };
const PROVIDERS = { google: "Google", apple: "Apple", microsoft: "Microsoft", github: "GitHub", facebook: "Facebook", gitlab: "GitLab", twitter: "X", linkedin: "LinkedIn", amazon: "Amazon", slack: "Slack" };
const MESSAGES = {
  Denied: "That login isn't for this page.",
  Reprompt: "This item asks for your master password: use it from Passwords.",
  RateLimited: "Too many requests; wait a minute.",
  NoField: "This item doesn't have that.",
  NoForm: "Nothing on this page to fill.",
  NoUrl: "This page can't be filled.",
  NoPassword: "Type the username and password into the page's form first.",
  Clipboard: "Couldn't copy: the desktop has no clipboard for Passwords.",
  Locked: "Passwords is locked.",
  Failed: "Couldn't do that: is Passwords online?",
};
const say = (r, fallback) => MESSAGES[r?.error] ?? fallback;

let site = { host: "", items: [] };
let flags = new Map();
let results = [];
let filter = "all";
let selected = null; // an item id, "generator" or "settings"
let rows = [];
let detailTimers = [];
let stateTimers = [];

// ---- feedback ----

let toastTimer;
function toast(text, error = false) {
  const t = $("toast");
  t.className = `toast${error ? " error" : ""}`;
  t.replaceChildren(icon(error ? "warning" : "check"), el("span", {}, text));
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), 3500);
}

async function copy(id, field, what) {
  const r = await ask({ cmd: "copy", id, field });
  if (r.seconds !== undefined) toast(`${what} copied${r.seconds ? ` · clears in ${r.seconds} s` : ""}`);
  else toast(say(r, "Couldn't copy."), true);
}

async function fill(id, confirmed = false) {
  const r = await ask({ cmd: "fill", id, confirmed });
  if (r.filled) window.close();
  else toast(say(r, "Couldn't fill."), true);
  return r;
}

// ---- the countdown ring of a one-time code ----

function ring(size = 26) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 22 22");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.classList.add("ring");
  const circle = (cls) => {
    const c = document.createElementNS(ns, "circle");
    for (const [k, v] of [["cx", "11"], ["cy", "11"], ["r", "9"], ["fill", "none"], ["stroke-width", "2.2"], ["class", cls]]) c.setAttribute(k, v);
    return c;
  };
  const fill = circle("fill");
  const length = 2 * Math.PI * 9;
  fill.setAttribute("stroke-dasharray", String(length));
  fill.setAttribute("stroke-linecap", "round");
  fill.setAttribute("transform", "rotate(-90 11 11)");
  const label = document.createElementNS(ns, "text");
  label.setAttribute("x", "11");
  label.setAttribute("y", "14");
  label.setAttribute("text-anchor", "middle");
  svg.append(circle("track"), fill, label);
  // Fills up as the code's time runs out, like the app's.
  svg.update = (period) => {
    const now = Date.now() / 1000;
    const left = Math.max(1, Math.ceil(period - (now % period)));
    fill.setAttribute("stroke-dashoffset", String(length * (1 - (now % period) / period)));
    label.textContent = String(left);
    svg.classList.toggle("ending", left <= 5);
  };
  return svg;
}

// ---- states before the vault is open ----

function showState(...children) {
  for (const t of stateTimers) clearInterval(t);
  stateTimers = [];
  panes.hidden = true;
  header.classList.add("hidden-search");
  $("actions").replaceChildren();
  stateView.hidden = false;
  stateView.replaceChildren(tile({ kind: "key", name: "" }, 64), ...children);
}

async function refresh() {
  const s = await ask({ cmd: "status" });
  switch (s.state) {
    case "unavailable":
      return showState(
        el("h1", {}, "Passwords isn't running"),
        el("p", {}, "Nyx Passwords isn't installed on this computer, or its service couldn't start."),
        el("div", { class: "buttons" }, el("button", { class: "primary", onclick: refresh }, "Try again")),
      );
    case "unpaired":
      return showState(
        el("h1", {}, "Connect to Nyx Passwords"),
        el("p", {}, "Pair this browser with the Passwords app on this computer. Your vault stays in the app; the extension asks it for one thing at a time."),
        el("div", { class: "buttons" }, el("button", { class: "primary", onclick: startPairing }, icon("link"), "Pair with Passwords")),
      );
    case "pending":
      return waitForConfirmation();
    case "locked":
      return showState(
        el("h1", {}, "Passwords is locked"),
        el("p", {}, "Unlock it in the app to fill logins, codes and cards here."),
        el("div", { class: "buttons" }, el("button", { class: "primary", onclick: () => ask({ cmd: "unlock" }).then(() => window.close()) }, icon("lock"), "Unlock in Passwords")),
      );
    case "unlocked":
      return openVault();
    default:
      return showState(
        el("h1", {}, "Couldn't reach Passwords"),
        el("p", {}, "Try again in a moment."),
        el("div", { class: "buttons" }, el("button", { class: "primary", onclick: refresh }, "Try again")),
      );
  }
}

async function startPairing() {
  const answer = await ask({ cmd: "pair" });
  if (answer.state !== "pending") {
    return showState(
      el("h1", {}, answer.state === "locked" ? "Unlock Passwords first" : "Pairing didn't start"),
      el("p", {}, answer.state === "locked" ? "Pairing needs the vault open. Unlock it in the app, then pair." : "Is Passwords running? Try again."),
      el("div", { class: "buttons" }, el("button", { onclick: refresh }, "Back")),
    );
  }
  waitForConfirmation(answer.code);
}

function waitForConfirmation(code) {
  showState(
    el("h1", {}, "Confirm in Passwords"),
    el("p", {}, code ? "Passwords shows a pairing request. Confirm it there if it shows this code:" : "Passwords shows a pairing request: confirm it there."),
    code ? el("div", { class: "code" }, `${code.slice(0, 3)} ${code.slice(3)}`) : null,
    el("div", { class: "buttons dim" }, el("span", { class: "spinner" }), "Waiting for confirmation…"),
  );
  stateTimers.push(
    setInterval(async () => {
      const s = await ask({ cmd: "status" });
      if (s.state !== "pending") refresh();
    }, 1500),
  );
}

// ---- the vault ----

async function openVault() {
  for (const t of stateTimers) clearInterval(t);
  stateView.hidden = true;
  panes.hidden = false;
  header.classList.remove("hidden-search");
  const action = (name, title, onclick, id) => el("button", { class: "icon", title, onclick, id }, icon(name));
  $("actions").replaceChildren(
    action("wand", "Generate a password", () => select("generator"), "act-generator"),
    action("lock", "Lock Passwords", async () => {
      await ask({ cmd: "lock" });
      refresh();
    }),
    action("settings", "Settings", () => select("settings"), "act-settings"),
  );
  site = await ask({ cmd: "match" });
  site.items ??= [];
  flags = new Map();
  if (site.items.length) {
    const s = await ask({ cmd: "security", ids: site.items.map((i) => i.id) });
    for (const f of s.items ?? []) flags.set(f.id, f);
  }
  await runSearch();
  select(selected ?? site.items[0]?.id ?? null);
  search.focus();
}

let searchSerial = 0;
async function runSearch() {
  const mine = ++searchSerial;
  const found = await ask({ cmd: "search", q: search.value });
  if (mine !== searchSerial) return;
  results = found.items ?? [];
  renderList();
}

function matchesFilter(item) {
  return filter === "all" || (item.kind ?? "login") === filter;
}

function renderList() {
  rows = [];
  const filters = el("div", { class: "segmented" });
  for (const [k, label, name] of [["all", "All"], ["login", "Logins", "login"], ["card", "Cards", "card"], ["identity", "Identities", "identity"], ["note", "Notes", "note"]]) {
    filters.append(
      el("button", { class: filter === k ? "on" : "", title: label, onclick: () => { filter = k; renderList(); } }, name ? icon(name, 15) : label),
    );
  }
  const parts = [el("div", { class: "filters" }, filters)];
  const query = search.value.trim();
  if (!query) {
    if (filter === "all" || filter === "login") {
      parts.push(el("div", { class: "group-label" }, "Suggested", site.host ? el("span", { class: "host" }, `· ${site.host}`) : null));
      if (site.items.length) for (const i of site.items) parts.push(row({ ...i, kind: "login" }, true));
      else parts.push(el("div", { class: "empty-line" }, site.host ? "No logins saved for this site." : "This page can't be filled."));
    }
    const shown = results.filter(matchesFilter).filter((i) => !site.items.some((s) => s.id === i.id));
    const favorites = shown.filter((i) => i.favorite);
    const rest = shown.filter((i) => !i.favorite);
    if (favorites.length) parts.push(el("div", { class: "group-label" }, "Favorites"), ...favorites.map((i) => row(i)));
    if (rest.length) parts.push(el("div", { class: "group-label" }, filter === "all" ? "All items" : `${KINDS[filter]}s`), ...rest.map((i) => row(i)));
  } else {
    const shown = results.filter(matchesFilter);
    parts.push(el("div", { class: "group-label" }, shown.length ? `${shown.length} found` : "Nothing found"));
    parts.push(...shown.map((i) => row(i)));
  }
  list.replaceChildren(...parts);
  markSelected();
}

function subtitle(item) {
  if (item.sign_in_with && !item.has_password) return `Sign in with ${PROVIDERS[item.sign_in_with] ?? item.sign_in_with}`;
  return item.username || item.sub || item.host || KINDS[item.kind] || "";
}

function row(item, suggested = false) {
  const r = el(
    "div",
    { class: "row", tabindex: "-1", "data-id": item.id },
    tile(item, 32),
    el("div", { class: "text" }, el("div", { class: "title" }, item.name), el("div", { class: "sub" }, subtitle(item))),
    item.favorite ? el("span", { class: "star", title: "Favorite" }, icon("star", 13)) : null,
    suggested && (item.has_password || item.username || item.sign_in_with)
      ? el("button", { class: "primary small quick", title: "Fill this login into the page (Enter)", onclick: (e) => { e.stopPropagation(); autofill(item); } }, "Fill")
      : null,
  );
  r.addEventListener("click", () => select(item.id));
  r.addEventListener("dblclick", () => primary(item));
  rows.push({ item, node: r });
  return r;
}

function markSelected() {
  for (const { item, node } of rows) node.classList.toggle("selected", item.id === selected);
  const actions = { generator: "act-generator", settings: "act-settings" };
  for (const [k, id] of Object.entries(actions)) $(id)?.classList.toggle("on", selected === k);
}

function primary(item) {
  if ((item.kind ?? "login") === "login") return autofill(item);
  if (item.kind === "card" || item.kind === "identity") return fillItem(item);
}

async function autofill(item) {
  const here = site.items.find((i) => i.id === item.id);
  if (here?.sign_in_with && !here.has_password) {
    const r = await ask({ cmd: "signin", provider: here.sign_in_with });
    if (r.clicked) return window.close();
    return toast(`Couldn't find “Sign in with ${PROVIDERS[here.sign_in_with] ?? here.sign_in_with}” on this page.`, true);
  }
  if (!here) return select(item.id, { confirmFill: true });
  return fill(item.id);
}

async function fillItem(item) {
  const r = await ask({ cmd: "fill_item", id: item.id, kind: item.kind });
  if (r.filled) window.close();
  else toast(say(r, "Couldn't fill."), true);
}

// ---- the right side ----

function clearDetail() {
  for (const t of detailTimers) clearInterval(t);
  detailTimers = [];
}

let detailSerial = 0;
async function select(what, options = {}) {
  selected = what;
  markSelected();
  clearDetail();
  const mine = ++detailSerial;
  if (what === "generator") return generator();
  if (what === "settings") return settings();
  if (!what) return placeholder();
  const item = await ask({ cmd: "item", id: what });
  if (mine !== detailSerial) return;
  if (item.error) {
    detail.replaceChildren();
    return toast(say(item, "Couldn't open it."), true);
  }
  itemView(item, options);
}

function placeholder() {
  detail.replaceChildren(
    el(
      "div",
      { class: "placeholder" },
      tile({ kind: "key" }, 52),
      el("div", { class: "big" }, site.host ? `Nothing saved for ${site.host}` : "Pick an item"),
      el("div", {}, site.host ? "Save the login you type into the page, or make a new password for it." : "Search your vault, or pick an item on the left."),
      site.host
        ? el(
            "div",
            { class: "bar" },
            el("button", { class: "primary", onclick: saveFromPage }, icon("plus"), "Save login from page"),
            el("button", { onclick: () => select("generator") }, icon("wand"), "New password"),
          )
        : null,
    ),
  );
}

async function saveFromPage() {
  const r = await ask({ cmd: "save" });
  if (r.saved === "created") toast(`Saved a new login${r.username ? ` for ${r.username}` : ""}`);
  else if (r.saved === "updated") toast(`Updated the password for ${r.username || "this login"}`);
  else return toast(say(r, "Couldn't save the login."), true);
  selected = r.id ?? null;
  openVault();
}

function field({ label, value, cls = "", onclick, actions = [], title }) {
  return el(
    "div",
    { class: `field${onclick ? "" : " static"}`, onclick, title },
    el("div", { class: "text" }, el("div", { class: "label" }, label), el("div", { class: `value ${cls}` }, value)),
    actions.length ? el("div", { class: "actions" }, ...actions) : null,
  );
}

const copyButton = (title, onclick) => el("button", { class: "icon small", title, onclick: (e) => { e.stopPropagation(); onclick(); } }, icon("copy", 15));

function itemView(item, { confirmFill = false } = {}) {
  const kind = item.kind ?? "login";
  const here = site.items.find((i) => i.id === item.id);
  const parts = [];
  const hostLine = item.host ? ` · ${item.host}` : "";
  parts.push(
    el(
      "div",
      { class: "head" },
      tile(item, 44),
      el("div", { class: "text" }, el("div", { class: "name" }, item.name), el("div", { class: "sub" }, `${KINDS[kind] ?? "Item"}${hostLine}`)),
      item.favorite ? el("span", { class: "star", title: "Favorite" }, icon("star")) : null,
    ),
  );

  const bar = el("div", { class: "bar" });
  if (kind === "login" && (item.has_password || item.username || item.sign_in_with)) {
    const via = here?.sign_in_with && !here.has_password ? PROVIDERS[here.sign_in_with] ?? here.sign_in_with : null;
    bar.append(
      el("button", { class: "primary", title: "Fill into the page (Enter)", onclick: () => autofill(item) }, icon("fill"), via ? `Sign in with ${via}` : here ? "Autofill" : "Fill on this site…"),
    );
  } else if (kind === "card" || kind === "identity") {
    bar.append(el("button", { class: "primary", title: "Fill into the page's form (Enter)", onclick: () => fillItem(item) }, icon("fill"), "Autofill"));
  }
  if (bar.childElementCount) parts.push(bar);

  if (confirmFill && kind === "login") parts.push(confirmBanner(item));

  const f = flags.get(item.id);
  if (f && (f.weak || f.reused || f.old)) {
    const what = [f.weak && "weak", f.reused && "used for other logins too", f.old && "over a year old"].filter(Boolean);
    parts.push(
      el(
        "div",
        { class: "banner" },
        icon("shield"),
        el("div", {}, el("div", { class: "title" }, "Change this password"), el("div", { class: "dim" }, `It's ${what.join(", and ")}. Make a new one in Passwords.`)),
      ),
    );
  }
  if (item.reprompt) parts.push(el("div", { class: "banner info" }, icon("lock"), el("div", {}, "This item asks for your master password, so it's filled and copied from Passwords only.")));

  const fields = el("div", { class: "card fields" });
  if (kind === "login") {
    if (item.username) fields.append(field({ label: "username", value: item.username, title: "Click to copy", onclick: () => copy(item.id, "username", "Username"), actions: [copyButton("Copy the username", () => copy(item.id, "username", "Username"))] }));
    if (item.has_password) fields.append(field({ label: "password", value: "••••••••••••", cls: "secret", title: "Click to copy", onclick: () => copy(item.id, "password", "Password"), actions: [copyButton("Copy the password", () => copy(item.id, "password", "Password"))] }));
    if (item.has_totp) fields.append(totpField(item, Boolean(here)));
    if (item.has_passkey) fields.append(field({ label: "passkey", value: el("span", {}, "Saved in Passwords"), actions: [] }));
    if (item.sign_in_with) fields.append(field({ label: "signs in with", value: PROVIDERS[item.sign_in_with] ?? item.sign_in_with }));
  } else if (item.sub) {
    fields.append(field({ label: kind === "card" ? "card" : "name", value: item.sub }));
  }
  if (fields.childElementCount) parts.push(fields);

  if (kind === "note" || kind === "ssh" || kind === "other") {
    parts.push(el("div", { class: "banner info" }, icon(kind === "ssh" ? "ssh" : "note"), el("div", {}, el("div", {}, `${KINDS[kind]}s stay in the app: open Passwords to read or copy them.`), el("div", { class: "buttons" }, el("button", { onclick: () => ask({ cmd: "unlock" }) }, "Open Passwords")))));
  } else if (kind === "card" || kind === "identity") {
    parts.push(el("div", { class: "dim", style: "padding: 0 4px 12px; line-height: 1.45" }, kind === "card" ? "Fills a checkout form on https pages. The menu in a card field offers it too." : "Fills an address or sign-up form. The menu in its fields offers it too."));
  }

  const uris = (item.uris ?? []).filter(Boolean);
  if (uris.length) {
    parts.push(el("div", { class: "section-label" }, uris.length > 1 ? "Websites" : "Website"));
    const box = el("div", { class: "card fields" });
    for (const u of uris) {
      const href = /^[a-z][a-z0-9+.-]*:/i.test(u) ? u : `https://${u}`;
      const open = () => api.tabs.create({ url: href }).then(() => window.close());
      const openable = /^https?:/i.test(href);
      box.append(
        field({
          label: "website",
          value: u,
          onclick: openable ? open : undefined,
          title: openable ? "Open in a new tab" : undefined,
          actions: [
            copyButton("Copy the address", () => navigator.clipboard.writeText(u).then(() => toast("Address copied"))),
            openable ? el("button", { class: "icon small", title: "Open in a new tab", onclick: (e) => { e.stopPropagation(); open(); } }, icon("external", 15)) : null,
          ].filter(Boolean),
        }),
      );
    }
    parts.push(box);
  }
  detail.replaceChildren(...parts);
}

function totpField(item, here) {
  const r = ring(28);
  const code = el("span", {}, here ? "··· ···" : "From Passwords");
  const node = field({ label: "one-time code", value: code, cls: here ? "code" : "", title: "Click to copy", onclick: () => copy(item.id, "totp", "One-time code"), actions: [copyButton("Copy the one-time code", () => copy(item.id, "totp", "One-time code"))] });
  node.prepend(r);
  node.querySelector(".actions").classList.add("always");
  let period = 30;
  let step = -1;
  const load = async () => {
    if (!here) return;
    const answer = await ask({ cmd: "totp", id: item.id });
    if (!answer.code) return void (code.textContent = say(answer, "—"));
    period = answer.period ?? 30;
    step = Math.floor(Date.now() / 1000 / period);
    const c = answer.code;
    code.textContent = c.length >= 6 ? `${c.slice(0, c.length / 2)} ${c.slice(c.length / 2)}` : c;
  };
  load();
  r.update(period);
  detailTimers.push(
    setInterval(() => {
      r.update(period);
      if (here && Math.floor(Date.now() / 1000 / period) !== step) load();
    }, 250),
  );
  return node;
}

// Another site's login: say so before filling, then offer to add this site to it.
function confirmBanner(item) {
  const where = item.host || "another site";
  const box = el(
    "div",
    { class: "banner" },
    icon("warning"),
    el(
      "div",
      {},
      el("div", { class: "title" }, `This login is for ${where}`),
      el("div", { class: "dim" }, `Fill it into ${site.host || "this page"} anyway? Only do this if you trust the page.`),
      el(
        "div",
        { class: "buttons" },
        el("button", { class: "primary small", onclick: async () => {
          const r = await ask({ cmd: "fill", id: item.id, confirmed: true });
          if (!r.filled) return toast(say(r, "Couldn't fill."), true);
          box.replaceWith(
            el("div", { class: "banner info" }, icon("link"), el("div", {},
              el("div", { class: "title" }, `Filled. Add ${site.host} to this login?`),
              el("div", { class: "dim" }, "Then it's suggested here next time."),
              el("div", { class: "buttons" },
                el("button", { class: "primary small", onclick: async () => {
                  const a = await ask({ cmd: "add_uri", id: item.id });
                  if (a.error) toast(say(a, "Couldn't add it."), true);
                  else window.close();
                } }, "Add"),
                el("button", { class: "small", onclick: () => window.close() }, "Not now")))),
          );
        } }, "Fill anyway"),
        el("button", { class: "small", onclick: () => box.remove() }, "Cancel"),
      ),
    ),
  );
  return box;
}

// ---- the generator ----

const genOptions = { kind: "password", length: 20, uppercase: true, lowercase: true, digits: true, symbols: true, words: 5 };

function generator() {
  const value = el("div", { class: "generated card" });
  let current = "";
  const show = (text) => {
    current = text;
    value.replaceChildren(...[...text].map((ch) => (/\d/.test(ch) ? el("span", { class: "d" }, ch) : /[^\p{L}\p{N}]/u.test(ch) && genOptions.kind === "password" ? el("span", { class: "s" }, ch) : ch)));
  };
  const make = async () => {
    const o = genOptions;
    const r =
      o.kind === "username"
        ? await ask({ cmd: "username" })
        : await ask({
            cmd: "generate",
            rules: o.kind === "password"
              ? { kind: "password", length: o.length, uppercase: o.uppercase, lowercase: o.lowercase, digits: o.digits, symbols: o.symbols, avoid_ambiguous: false }
              : { kind: "passphrase", words: o.words, separator: "-", capitalize: true, number: true },
          });
    const made = r.password ?? r.username;
    if (made) show(made);
    else value.replaceChildren(el("span", { class: "dim" }, say(r, r.message ?? "Couldn't make one.")));
  };
  const kinds = el("div", { class: "segmented", style: "margin-bottom: 12px" });
  for (const [k, label] of [["password", "Password"], ["passphrase", "Passphrase"], ["username", "Username"]]) {
    kinds.append(el("button", { class: genOptions.kind === k ? "on" : "", onclick: () => { genOptions.kind = k; generator(); } }, label));
  }
  const options = el("div", { class: "card", style: "margin-top: 12px" });
  const slider = (label, key, min, max) => {
    const count = el("span", { class: "count" }, String(genOptions[key]));
    const input = el("input", { type: "range", min: String(min), max: String(max), value: String(genOptions[key]) });
    input.addEventListener("input", () => (count.textContent = input.value));
    input.addEventListener("change", () => { genOptions[key] = Number(input.value); make(); });
    return el("div", { class: "option" }, el("div", { class: "title", style: "width: 70px" }, label), input, count);
  };
  if (genOptions.kind === "password") {
    options.append(slider("Length", "length", 8, 64));
    const chips = el("div", { class: "checks" });
    for (const [k, label] of [["uppercase", "A–Z"], ["lowercase", "a–z"], ["digits", "0–9"], ["symbols", "!@#"]]) {
      const b = el("button", { class: `chip${genOptions[k] ? " on" : ""}`, onclick: () => {
        genOptions[k] = !genOptions[k];
        if (!["uppercase", "lowercase", "digits", "symbols"].some((x) => genOptions[x])) genOptions.lowercase = true;
        generator();
      } }, label);
      chips.append(b);
    }
    options.append(el("div", { class: "option" }, el("div", { class: "title", style: "width: 70px" }, "Use"), chips));
  } else if (genOptions.kind === "passphrase") {
    options.append(slider("Words", "words", 3, 10));
  } else {
    options.append(el("div", { class: "option" }, el("div", { class: "text" }, el("div", { class: "title" }, "As set in Passwords"), el("div", { class: "desc" }, "A random word, your email with a tag, a catch-all address or a new alias, from Passwords → Settings → Generator."))));
  }
  const bar = el(
    "div",
    { class: "bar", style: "margin-top: 14px" },
    el("button", { class: "primary", title: "Put it in the page's new-password fields", onclick: async () => {
      const r = await ask({ cmd: "fill_generated", value: current });
      if (r.filled) window.close();
      else toast(say(r, "No empty password field on this page."), true);
    } }, icon("fill"), "Fill into page"),
    el("button", { onclick: () => navigator.clipboard.writeText(current).then(() => toast("Copied")) }, icon("copy"), "Copy"),
    el("button", { class: "icon", title: "Make another", onclick: make }, icon("refresh")),
  );
  detail.replaceChildren(el("div", { class: "head" }, tile({ kind: "wand" }, 44), el("div", { class: "text" }, el("div", { class: "name" }, "Generator"), el("div", { class: "sub" }, "Passwords keeps what it made until the vault locks"))), kinds, value, options, bar);
  make();
}

// ---- settings ----

async function settings() {
  const s = await ask({ cmd: "settings" });
  if (selected !== "settings") return;
  const option = (key, title, desc) => {
    const input = el("input", { type: "checkbox", class: "switch" });
    input.checked = Boolean(s[key]);
    input.addEventListener("change", () => ask({ cmd: "set", key, value: input.checked }));
    return el("label", { class: "option" }, el("div", { class: "text" }, el("div", { class: "title" }, title), el("div", { class: "desc" }, desc)), input);
  };
  const appSays = (on, what) => (on === false ? ` Off in Passwords → Settings → Browsers, which ${what}.` : "");
  detail.replaceChildren(
    el("div", { class: "head" }, tile({ kind: "settings" }, 44), el("div", { class: "text" }, el("div", { class: "name" }, "Settings"), el("div", { class: "sub" }, "For this browser; the vault's own are in Passwords"))),
    el("div", { class: "section-label" }, "Filling"),
    el(
      "div",
      { class: "card", style: "margin-bottom: 14px" },
      option("fillOnLoad", "Fill logins as pages load", `Only on https, only the login saved for that exact site, only into empty fields.${appSays(s.app?.fill_on_load, "decides first")}`),
      option("inlineMenu", "Menu in fields", "Your logins, cards and addresses under the field you click."),
      option("copyTotp", "Copy the one-time code after filling", "Passwords clears the clipboard later."),
    ),
    el("div", { class: "section-label" }, "Signing in"),
    el(
      "div",
      { class: "card", style: "margin-bottom: 14px" },
      option("rememberSignIn", "Remember “Sign in with …”", "After you sign in with Google, Apple, GitHub and the like, offer to click it for you next time."),
      option("passkeys", "Passkeys", `Sites can use and save passkeys in your vault; you confirm each in a small window.${appSays(s.app?.passkeys, "must allow it too")}`),
    ),
    el("div", { class: "section-label" }, "This browser"),
    el(
      "div",
      { class: "card option" },
      el("div", { class: "text" }, el("div", { class: "title" }, "Paired with Passwords"), el("div", { class: "desc" }, "Unpairing stops this browser from asking Passwords for anything until you pair it again.")),
      el("button", { class: "danger", onclick: async () => {
        await ask({ cmd: "unpair" });
        refresh();
      } }, "Unpair"),
    ),
  );
}

// ---- keys ----

search.addEventListener("input", () => {
  clearTimeout(search.timer);
  search.timer = setTimeout(runSearch, 70);
});
document.addEventListener("keydown", (e) => {
  if (panes.hidden) return;
  const inField = document.activeElement?.tagName === "INPUT" && document.activeElement !== search;
  if (inField) return;
  if (e.key === "/" && document.activeElement !== search) {
    e.preventDefault();
    search.focus();
    return;
  }
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    const at = rows.findIndex((r) => r.item.id === selected);
    const next = rows[Math.min(rows.length - 1, Math.max(0, at + (e.key === "ArrowDown" ? 1 : -1)))];
    if (next) {
      select(next.item.id);
      next.node.scrollIntoView({ block: "nearest" });
    }
    return;
  }
  if (e.key === "Enter" && document.activeElement === search) {
    const current = rows.find((r) => r.item.id === selected) ?? rows[0];
    if (current) primary(current.item);
    return;
  }
  if (e.key === "Escape" && search.value) {
    e.preventDefault();
    search.value = "";
    runSearch();
  }
});

$("brand").append(icon("key", 16));
$("search-icon").append(icon("search", 15));
if (location.hash === "#welcome") {
  document.body.classList.add("welcome");
  document.title = "Welcome to Nyx Passwords";
}
refresh();
