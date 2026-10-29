// The menu under a page's field: the page's logins (or cards, or addresses), a new
// password for sign-up forms, one-time codes, "Sign in with …". It runs as this
// extension's page inside the frame, so the page can't read it; picking an entry asks
// the background script to fill, which asks the app.

const { api, el, icon, tile } = NYX;
const token = location.hash.slice(1);
const list = document.getElementById("list");
const ask = (cmd, extra = {}) => api.runtime.sendMessage({ cmd, token, ...extra });
const close = () => parent.postMessage({ nyx: "menu-close" }, "*");
const fit = () => parent.postMessage({ nyx: "menu-height", height: document.body.scrollHeight + 2 }, "*");

const PROVIDERS = { google: "Google", apple: "Apple", microsoft: "Microsoft", github: "GitHub", facebook: "Facebook", gitlab: "GitLab", twitter: "X", linkedin: "LinkedIn", amazon: "Amazon", slack: "Slack" };

function row(lead, title, sub, act) {
  const r = el("div", { class: "row", tabindex: "0" }, lead, el("div", { class: "text" }, el("div", { class: "title" }, title), sub ? el("div", { class: "sub" }, sub) : null), el("span", { class: "go" }, icon("fill", 15)));
  const go = async () => {
    const answer = await act();
    if (answer?.error === "Reprompt") return note("This item asks for your master password: fill it from Passwords.", true);
    if (answer?.error) return note(answer.error === "NoForm" ? "Nothing here to fill." : "Couldn't fill.", true);
    close();
  };
  r.addEventListener("click", go);
  r.addEventListener("keydown", (e) => {
    if (e.key === "Enter") go();
    if (e.key === "ArrowDown") r.nextElementSibling?.focus();
    if (e.key === "ArrowUp") r.previousElementSibling?.focus();
    if (e.key === "Escape") close();
  });
  list.append(r);
}

const kindTile = (name) => el("span", { class: "tile kind", style: "--size:28px" }, icon(name, 14));

function note(text, error = false) {
  list.querySelector(".note")?.remove();
  list.prepend(el("div", { class: `note${error ? " error" : ""}` }, text));
  fit();
}

async function show() {
  document.getElementById("mark").append(icon("key", 11));
  const state = await ask("menu.items");
  if (state?.state === "locked") {
    row(kindTile("lock"), "Unlock Passwords", "The vault is locked", () => ask("menu.unlock"));
    return fit();
  }
  if (state?.state !== "unlocked") {
    note("Nyx Passwords isn't reachable.");
    return;
  }
  document.getElementById("host").textContent = state.host ?? "";
  const items = state.items ?? [];
  switch (state.field) {
    case "card":
    case "identity":
      for (const i of items) row(tile({ kind: state.field, name: i.name }, 28), i.name, i.sub, () => ask("menu.form", { id: i.id }));
      if (!items.length) note(state.field === "card" ? "No cards saved in Passwords." : "No identities saved in Passwords.");
      break;
    case "otp":
      for (const i of items.filter((i) => i.has_totp)) row(kindTile("clock"), `Code for ${i.name}`, i.username, () => ask("menu.code", { id: i.id }));
      if (!items.some((i) => i.has_totp)) note("No login for this site has a one-time code.");
      break;
    case "new-password":
      row(kindTile("wand"), "Generate a password", "Into this form's new password fields", () => ask("menu.generate"));
      if (items.length) list.append(el("div", { class: "sep" }));
      for (const i of items) row(tile(i, 28), i.name, i.username || "No username", () => ask("menu.fill", { id: i.id }));
      break;
    default:
      for (const i of items) {
        if (i.sign_in_with && !i.has_password) {
          const name = PROVIDERS[i.sign_in_with] ?? i.sign_in_with;
          row(kindTile("signin"), `Sign in with ${name}`, i.username || i.name, () => ask("menu.signin", { provider: i.sign_in_with }));
        } else {
          row(tile(i, 28), i.name, i.username || "No username", () => ask("menu.fill", { id: i.id }));
        }
      }
      if (!items.length) note("No logins saved for this site.");
  }
  fit();
}

show();
