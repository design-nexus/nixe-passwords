// Runs in every page frame (isolated from the page's own scripts). It notices login,
// sign-up, one-time-code, card and address fields, and opens this extension's menu
// under them; it reports submitted logins (for the save bar) and clicks on "Sign in
// with …" buttons. It never sees a vault value: filling is done by the background
// script, into this frame, after the app checked the page.

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (globalThis.__nyxPasswords) return;
  globalThis.__nyxPasswords = true;

  const visible = (el) => el.offsetParent !== null && !el.disabled && !el.readOnly && el.getBoundingClientRect().width > 0;
  const text = (el) => `${el.name} ${el.id} ${el.placeholder ?? ""} ${el.getAttribute("aria-label") ?? ""} ${el.autocomplete ?? ""}`.toLowerCase();

  /// What a field is for, or null.
  function kindOf(el) {
    if (!(el instanceof HTMLInputElement) || !visible(el)) return null;
    const ac = (el.autocomplete || "").toLowerCase();
    const t = text(el);
    if (ac.includes("one-time-code") || /otp|totp|2fa|mfa|one.?time|verification.?code|auth.?code/.test(t)) return "otp";
    if (ac.startsWith("cc-") || /card.?number|cc.?num|cvc|cvv|csc|card.?holder|expir/.test(t)) return "card";
    if (el.type === "password") {
      const passwords = [...(el.form ?? document).querySelectorAll('input[type="password"]')].filter(visible);
      return ac.includes("new-password") || passwords.length > 1 || /new|confirm|repeat|create/.test(t) ? "new-password" : "login";
    }
    if (["text", "email", "tel", ""].includes(el.type)) {
      if (/username|email/.test(ac) || /user|login|e.?mail|account/.test(t)) {
        const form = el.form ?? document;
        // A username with a password near it, or on its own (the first step of a login).
        if (form.querySelector('input[type="password"]') || el.form) return "login";
      }
      if (/given-name|family-name|street-address|address-line|postal-code|country|tel$/.test(ac) || /first.?name|last.?name|address|postal|zip|city/.test(t)) {
        return "identity";
      }
    }
    return null;
  }

  // ---- the menu under a field ----

  let host = null;
  let frame = null;
  let anchor = null;
  let closing = null;

  function closeMenu() {
    host?.remove();
    host = frame = anchor = null;
  }

  function place() {
    if (!host || !anchor) return;
    const r = anchor.getBoundingClientRect();
    host.style.top = `${r.bottom + window.scrollY + 4}px`;
    host.style.left = `${r.left + window.scrollX}px`;
    host.style.width = `${Math.min(380, Math.max(300, r.width))}px`;
  }

  async function openMenu(el, field) {
    if (anchor === el) return;
    closeMenu();
    const answer = await api.runtime.sendMessage({ cmd: "field", field }).catch(() => null);
    if (!answer?.token || document.activeElement !== el) return;
    // A closed shadow root: the page can't reach the frame or style it.
    host = document.createElement("nyx-passwords-menu");
    const shadow = host.attachShadow({ mode: "closed" });
    host.style.cssText = "position:absolute;z-index:2147483647;height:0;display:block;";
    frame = document.createElement("iframe");
    frame.src = api.runtime.getURL(`menu.html#${answer.token}`);
    frame.style.cssText = "border:0;width:100%;height:220px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.3),0 1px 3px rgba(0,0,0,.2);background:transparent;color-scheme:normal;";
    frame.setAttribute("allowtransparency", "true");
    shadow.append(frame);
    document.documentElement.append(host);
    anchor = el;
    place();
  }

  document.addEventListener(
    "focusin",
    (e) => {
      clearTimeout(closing);
      const field = kindOf(e.target);
      if (field) openMenu(e.target, field);
      else if (e.target !== host) closeMenu();
    },
    true,
  );
  document.addEventListener(
    "focusout",
    (e) => {
      if (e.target === anchor) closing = setTimeout(() => document.activeElement !== host && closeMenu(), 250);
    },
    true,
  );
  document.addEventListener("keydown", (e) => e.key === "Escape" && closeMenu(), true);
  window.addEventListener("scroll", place, { passive: true });
  window.addEventListener("resize", place, { passive: true });
  api.runtime.onMessage.addListener((message) => {
    if (message.cmd === "menu.close") closeMenu();
    if (message.cmd === "bar" && window === window.top) showBar(message.token);
  });

  // ---- the save bar ----

  let bar = null;
  function showBar(t) {
    bar?.remove();
    bar = document.createElement("nyx-passwords-bar");
    const shadow = bar.attachShadow({ mode: "closed" });
    bar.style.cssText = "position:fixed;top:12px;right:12px;z-index:2147483647;display:block;";
    const f = document.createElement("iframe");
    f.src = api.runtime.getURL(`bar.html#${t}`);
    f.style.cssText = "border:0;width:400px;height:152px;border-radius:14px;box-shadow:0 10px 30px rgba(0,0,0,.3),0 1px 3px rgba(0,0,0,.2);background:transparent;";
    shadow.append(f);
    document.documentElement.append(bar);
    setTimeout(() => {
      bar?.remove();
      bar = null;
    }, 60000);
  }
  // The menu and the bar close themselves (only their frames can ask: a page's own
  // message comes from the page's window).
  window.addEventListener("message", (e) => {
    if (e.source === window) return;
    if (e.data?.nyx === "bar-close") {
      bar?.remove();
      bar = null;
    }
    if (e.data?.nyx === "menu-close") closeMenu();
    if (e.data?.nyx === "menu-height" && frame && e.source === frame.contentWindow) {
      frame.style.height = `${Math.min(320, Math.max(48, Number(e.data.height) || 0))}px`;
    }
  });

  // ---- submitted logins ----

  // The login typed into a form, read as it's submitted. It goes to the background
  // script, which asks the app whether it's new or changed before offering to save.
  function capture(form) {
    const fields = [...(form ?? document).querySelectorAll("input")].filter((el) => el.offsetParent !== null);
    const password = fields.find((el) => el.type === "password" && el.value);
    if (!password) return;
    const before = fields.slice(0, fields.indexOf(password)).reverse();
    const user =
      before.find((el) => /username|email/.test(el.autocomplete) && el.value) ??
      before.find((el) => ["text", "email", "tel"].includes(el.type) && el.value);
    api.runtime.sendMessage({ cmd: "submitted", username: user?.value ?? "", password: password.value }).catch(() => {});
  }
  document.addEventListener("submit", (e) => capture(e.target), true);
  document.addEventListener(
    "click",
    (e) => {
      const button = e.target.closest?.('a, button, input[type="submit"], [role="button"]');
      if (!button) return;
      const label = `${button.textContent} ${button.value ?? ""} ${button.getAttribute("aria-label") ?? ""}`;
      if (button.tagName !== "A" && /log.?in|sign.?(in|up)|register|create|continue|next|submit|save/i.test(label)) {
        capture(button.closest("form"));
      }
      // Universal sign-on: "Sign in with Google" and the like.
      const href = button.href ?? button.closest("a")?.href ?? "";
      const providers = {
        google: /google/i, apple: /apple/i, microsoft: /microsoft|outlook/i, github: /github/i, facebook: /facebook/i,
        gitlab: /gitlab/i, twitter: /twitter/i, linkedin: /linkedin/i, amazon: /amazon/i, slack: /slack/i,
      };
      const domains = {
        google: /accounts\.google\.com/, apple: /appleid\.apple\.com/, microsoft: /login\.(microsoftonline|live)\.com/,
        github: /github\.com\/login\/oauth/, facebook: /facebook\.com\/.*oauth/, gitlab: /gitlab\.com\/oauth/,
      };
      for (const [name, word] of Object.entries(providers)) {
        if ((word.test(label) && /sign|log|continue|with/i.test(label)) || domains[name]?.test(href)) {
          api.runtime.sendMessage({ cmd: "provider", provider: name }).catch(() => {});
          break;
        }
      }
    },
    true,
  );

  // ---- filling as the page loads ----

  // Once per page load, if there's a login form (the background and the app decide
  // whether to fill, and only into empty fields).
  let asked = false;
  function maybeFillOnLoad() {
    if (asked) return;
    const password = [...document.querySelectorAll('input[type="password"]')].find(visible);
    if (!password || kindOf(password) !== "login") return;
    asked = true;
    api.runtime.sendMessage({ cmd: "loaded" }).catch(() => {});
  }
  if (document.readyState === "complete") maybeFillOnLoad();
  else window.addEventListener("load", maybeFillOnLoad, { once: true });
  // Forms drawn later by scripts.
  setTimeout(maybeFillOnLoad, 1500);

  // ---- passkeys, relayed from the page script ----

  window.addEventListener("message", async (e) => {
    if (e.source !== window || e.data?.nyx !== "webauthn" || !e.data.id) return;
    const { id, kind, options } = e.data;
    const answer = await api.runtime.sendMessage({ cmd: "passkey", kind, options }).catch(() => ({ fallback: true }));
    window.postMessage({ nyx: "webauthn-reply", id, answer: answer ?? { fallback: true } }, location.origin);
  });
})();
