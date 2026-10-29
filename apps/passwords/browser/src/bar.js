// The bar after signing in: save a new login, update a changed password, or remember
// which "Sign in with …" the site uses. It's this extension's page, so the page can't
// press its buttons; the login itself waits in the background script, not here.

const { api, el, icon, tile } = NYX;
const token = location.hash.slice(1);
const close = () => parent.postMessage({ nyx: "bar-close" }, "*");
const PROVIDERS = { google: "Google", apple: "Apple", microsoft: "Microsoft", github: "GitHub", facebook: "Facebook", gitlab: "GitLab", twitter: "X", linkedin: "LinkedIn", amazon: "Amazon", slack: "Slack" };

async function choose(choice) {
  const answer = await api.runtime.sendMessage({ cmd: "bar.answer", token, choice });
  if (answer?.error) {
    document.getElementById("detail").textContent = answer.error === "Failed" ? "Couldn't save: is Passwords online?" : `Couldn't save (${answer.error}).`;
    setTimeout(close, 2500);
    return;
  }
  close();
}

function button(label, choice, cls = "") {
  document.getElementById("buttons").append(el("button", { class: cls, onclick: () => choose(choice) }, label));
}

(async () => {
  document.getElementById("mark").append(icon("key", 11));
  const x = document.getElementById("close");
  x.append(icon("close", 14));
  x.addEventListener("click", () => choose("dismiss"));
  const s = await api.runtime.sendMessage({ cmd: "bar.state", token });
  if (!s) return close();
  const question = document.getElementById("question");
  const detail = document.getElementById("detail");
  const what = document.getElementById("what");
  if (s.question === "provider") {
    const name = PROVIDERS[s.provider] ?? s.provider;
    what.prepend(el("span", { class: "tile kind", style: "--size:38px" }, icon("signin", 18)));
    question.textContent = `Signed in with ${name}`;
    detail.textContent = `Remember it for ${s.host}, and click it for you next time?`;
    button("Not now", "dismiss", "ghost");
    button("Remember", "remember", "primary");
    return;
  }
  what.prepend(tile({ kind: "login", name: s.host.replace(/^www\./, ""), host: s.host.replace(/^www\./, "") }, 38));
  question.textContent = s.question === "changed" ? `Update the password for ${s.host}?` : `Save this login for ${s.host}?`;
  detail.textContent = s.username ? s.username : "No username";
  if (s.question !== "changed") button("Never for this site", "never", "ghost left");
  button("Not now", "dismiss", "ghost");
  button(s.question === "changed" ? "Update" : "Save", "save", "primary");
})();
