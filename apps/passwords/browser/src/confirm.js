// Confirming a passkey: this extension's own window, which a page can't draw or press.
// Signing in: pick the account. Making one: save it on a login for the site, or a new one.

const { api, el, icon, tile } = NYX;
const token = location.hash.slice(1);
const answer = (choice) => api.runtime.sendMessage({ cmd: "confirm.answer", token, choice }).then(() => window.close());

function row(lead, title, sub, choice) {
  const r = el("div", { class: "row", tabindex: "0" }, lead, el("div", { class: "text" }, el("div", { class: "title" }, title), el("div", { class: "sub" }, sub)));
  r.addEventListener("click", () => answer(choice));
  r.addEventListener("keydown", (e) => {
    if (e.key === "Enter") answer(choice);
    if (e.key === "ArrowDown") r.nextElementSibling?.focus();
    if (e.key === "ArrowUp") r.previousElementSibling?.focus();
  });
  document.getElementById("choices").append(r);
}

(async () => {
  document.getElementById("mark").append(icon("passkey", 22));
  const s = await api.runtime.sendMessage({ cmd: "confirm.state", token });
  if (!s) return window.close();
  const title = document.getElementById("title");
  const detail = document.getElementById("detail");
  const site = s.host.replace(/^www\./, "");
  if (s.ask === "get") {
    title.textContent = `Sign in to ${site}`;
    detail.textContent = "With a passkey from Passwords. Pick the account:";
    s.choices.forEach((c, index) => row(tile({ name: c.user_name || c.name, host: site }, 32), c.user_name || c.name, c.name, { index }));
  } else {
    title.textContent = `Save a passkey for ${site}`;
    detail.textContent = s.user ? `For ${s.user}. Keep it on:` : "Keep it on:";
    row(el("span", { class: "tile kind", style: "--size:32px" }, icon("plus", 16)), "A new login", s.rpId, { into: null, index: 0 });
    s.choices.forEach((c) => row(tile({ name: c.name, host: site }, 32), c.name, c.user_name || "No username", { into: c.id, index: 0 }));
  }
  document.getElementById("browser").addEventListener("click", () => answer(null));
  document.getElementById("cancel").addEventListener("click", () => answer(false));
  document.querySelector("#choices .row")?.focus();
})();
