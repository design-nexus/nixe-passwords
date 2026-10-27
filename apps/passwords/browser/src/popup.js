// The popup: pairing, unlocking, and the logins for the page in front. It never sees a
// password: filling happens from the background script straight into the page.

const api = globalThis.browser ?? globalThis.chrome;
const main = document.getElementById("main");
const footer = document.getElementById("footer");
const ask = (message) => api.runtime.sendMessage(message);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "onclick") node.addEventListener("click", v);
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

function show(...nodes) {
  main.replaceChildren(...nodes);
}

function note(text, kind = "") {
  return el("p", { class: `note ${kind}` }, text);
}

const MESSAGES = {
  Denied: "That login isn't for this page.",
  Reprompt: "This login asks for your master password: open it in Passwords.",
  RateLimited: "Too many requests; wait a minute.",
  NoField: "This login has no one-time code.",
  NoForm: "No login form found on this page.",
  NoUrl: "This page can't be filled.",
  NoPassword: "Type the username and password into the page's form first.",
  Failed: "Couldn't save: is Passwords online?",
};

async function refresh() {
  footer.replaceChildren();
  const status = await ask({ cmd: "status" });
  switch (status.state) {
    case "unavailable":
      return show(note("Nyx Passwords isn't installed on this computer, or couldn't start."));
    case "unpaired":
      return show(
        note("Pair this browser with Nyx Passwords to fill logins from your vault."),
        el("button", { class: "primary", onclick: startPairing }, "Pair with Passwords"),
      );
    case "pending":
      return waitForConfirmation();
    case "locked":
      return show(
        note("The vault is locked."),
        el("button", { class: "primary", onclick: () => ask({ cmd: "unlock" }).then(() => window.close()) }, "Unlock in Passwords"),
      );
    case "unlocked":
      return showLogins();
    default:
      return show(note("Couldn't reach Passwords. Try again in a moment."));
  }
}

async function startPairing() {
  const answer = await ask({ cmd: "pair" });
  if (answer.state !== "pending") {
    return show(note(answer.state === "locked" ? "Unlock Passwords first, then pair." : "Pairing didn't start."), el("button", { onclick: refresh }, "Back"));
  }
  waitForConfirmation(answer.code);
}

let polling = null;

function waitForConfirmation(code) {
  const parts = [note("Passwords shows a pairing request. Confirm it there if it shows this code:")];
  if (code) parts.push(el("p", { class: "code" }, `${code.slice(0, 3)} ${code.slice(3)}`));
  parts.push(note("Waiting for confirmation…", "dim"));
  show(...parts);
  clearInterval(polling);
  polling = setInterval(async () => {
    const status = await ask({ cmd: "status" });
    if (status.state !== "pending") {
      clearInterval(polling);
      refresh();
    }
  }, 1500);
}

async function showLogins() {
  const found = await ask({ cmd: "match" });
  document.getElementById("host").textContent = found.host ?? "";
  const items = found.items ?? [];
  const rows = items.map((item) => {
    const fill = el("button", { class: "primary", title: "Fill the username and password" }, "Fill");
    fill.addEventListener("click", async () => {
      const r = await ask({ cmd: "fill", id: item.id });
      if (r.filled) window.close();
      else status(MESSAGES[r.error] ?? r.error ?? "Couldn't fill.");
    });
    const actions = el("div", { class: "actions" }, fill);
    if (item.has_totp) {
      const otp = el("button", { title: "Copy the one-time code" }, "Code");
      otp.addEventListener("click", async () => {
        const r = await ask({ cmd: "totp", id: item.id });
        if (r.code) {
          await navigator.clipboard.writeText(r.code);
          status(`Code copied: it changes every 30 seconds.`);
        } else status(MESSAGES[r.error] ?? "Couldn't get the code.");
      });
      actions.append(otp);
    }
    return el(
      "div",
      { class: "item" },
      el("div", { class: "text" }, el("div", { class: "title" }, item.name), el("div", { class: "sub" }, item.username || "No username")),
      actions,
    );
  });
  show(...(rows.length ? rows : [note("No logins saved for this site.")]));
  const generate = el("button", { title: "Put a new password in this page's empty password fields" }, "Generate password");
  generate.addEventListener("click", async () => {
    const r = await ask({ cmd: "generate" });
    status(r.filled ? "Filled a new password. Save it in Passwords once you've signed up." : MESSAGES[r.error] ?? "No empty password field here.");
  });
  const save = el("button", { title: "Save the username and password typed into this page" }, "Save login");
  save.addEventListener("click", async () => {
    const r = await ask({ cmd: "save" });
    if (r.saved === "created") status(`Saved a new login${r.username ? ` for ${r.username}` : ""}.`);
    else if (r.saved === "updated") status(`Updated the password for ${r.username || "this login"}.`);
    else status(MESSAGES[r.error] ?? "Couldn't save the login.");
    if (r.saved) showLogins();
  });
  const unpair = el("button", { class: "flat", title: "Forget the pairing in this browser" }, "Unpair");
  unpair.addEventListener("click", async () => {
    await ask({ cmd: "unpair" });
    refresh();
  });
  footer.replaceChildren(generate, save, unpair);
}

function status(text) {
  const old = main.querySelector(".status");
  if (old) old.remove();
  main.prepend(note(text, "status"));
}

refresh();
