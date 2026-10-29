// Shared by the extension's pages: the suite's theme (as Passwords last reported it),
// the icons, and the small helpers every page builds with.

const NYX = (() => {
  const api = globalThis.browser ?? globalThis.chrome;
  const root = document.documentElement;

  // ---- the theme ----

  const luminance = (hex) => {
    const m = /^#?([0-9a-f]{6})/i.exec(hex ?? "");
    if (!m) return 0;
    const [r, g, b] = [0, 2, 4].map((i) => parseInt(m[1].slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
    return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  };
  const fonts = (list, fallback) =>
    `${(list ?? "").split(",").map((f) => f.trim()).filter(Boolean).map((f) => `"${f}"`).concat(fallback).join(", ")}`;

  let swatches = ["#5b9cff", "#9d7bff", "#ff6fae", "#ff6b6b", "#ff7a59", "#f2b545", "#46d08a", "#4cc9d6"];

  function apply(t) {
    if (t) {
      const set = (k, v) => v !== undefined && v !== null && v !== "" && root.style.setProperty(k, String(v));
      for (const k of ["bg", "panel", "card", "raised", "popover", "surface", "text", "dim", "tertiary", "accent", "border", "divider", "danger", "warning", "success"]) set(`--${k}`, t[k]);
      set("--hover-pct", `${Math.round((t.hover ?? 0.06) * 100)}%`);
      set("--selection-pct", `${Math.round((t.selection ?? 0.16) * 100)}%`);
      set("--on-accent", luminance(t.accent) > 0.3 ? "#0b0b0d" : "#ffffff");
      set("--font-ui", fonts(t.font_ui, ["Inter", "system-ui", "sans-serif"]));
      set("--font-mono", fonts(t.font_mono, ["JetBrains Mono", "ui-monospace", "monospace"]));
      set("--r-small", `${t.radius_small ?? 7}px`);
      set("--r-card", `${t.radius_card ?? 11}px`);
      set("--r-dialog", `${t.radius_dialog ?? 15}px`);
      set("--scale", t.text_scale ?? 1);
      root.dataset.light = t.light ? "true" : "false";
      if (t.swatches?.length) swatches = t.swatches.filter((s) => s.toLowerCase() !== "#a3a3ab");
    }
    root.classList.add("themed");
  }
  api.storage.local.get("theme").then(({ theme }) => apply(theme), () => apply());
  api.storage.onChanged.addListener((change) => change.theme && apply(change.theme.newValue));
  setTimeout(() => root.classList.add("themed"), 200);

  // ---- building ----

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else if (k === "class") node.className = v;
      else node.setAttribute(k, v === true ? "" : v);
    }
    for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c);
    return node;
  }

  // 16 px line icons, drawn for these pages in the suite's symbolic style.
  const PATHS = {
    search: '<circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5 14 14"/>',
    copy: '<rect x="5.5" y="5.5" width="8.5" height="8.5" rx="1.6"/><path d="M10.5 5.5V3.6A1.6 1.6 0 0 0 8.9 2H3.6A1.6 1.6 0 0 0 2 3.6v5.3a1.6 1.6 0 0 0 1.6 1.6h1.9"/>',
    key: '<circle cx="5" cy="11" r="3"/><path d="M7.2 8.8 13.5 2.5M11.2 4.8l1.8 1.8M12.8 3.2l1.4 1.4"/>',
    plus: '<path d="M8 3v10M3 8h10"/>',
    lock: '<rect x="3" y="7" width="10" height="7" rx="1.6"/><path d="M5.2 7V5.2a2.8 2.8 0 0 1 5.6 0V7"/>',
    settings: '<path d="M2 4.5h6M11 4.5h3M2 11.5h3M8 11.5h6"/><circle cx="9.5" cy="4.5" r="1.5"/><circle cx="6.5" cy="11.5" r="1.5"/>',
    globe: '<circle cx="8" cy="8" r="6"/><path d="M2 8h12M8 2c1.7 1.7 2.5 3.7 2.5 6S9.7 12.3 8 14C6.3 12.3 5.5 10.3 5.5 8S6.3 3.7 8 2z"/>',
    card: '<rect x="1.5" y="3.5" width="13" height="9" rx="1.6"/><path d="M1.5 6.5h13M4 10h3"/>',
    identity: '<circle cx="8" cy="5.5" r="2.5"/><path d="M3 13.5c.6-2.5 2.6-4 5-4s4.4 1.5 5 4"/>',
    note: '<rect x="3" y="1.5" width="10" height="13" rx="1.6"/><path d="M5.5 5h5M5.5 8h5M5.5 11h3"/>',
    ssh: '<rect x="1.5" y="2.5" width="13" height="11" rx="1.6"/><path d="M4.5 6l2 2-2 2M8.5 10.5h3"/>',
    login: '<circle cx="5" cy="11" r="3"/><path d="M7.2 8.8 13.5 2.5M11.2 4.8l1.8 1.8M12.8 3.2l1.4 1.4"/>',
    star: '<path d="M8 1.8l1.9 3.9 4.3.6-3.1 3 .7 4.3L8 11.6l-3.8 2 .7-4.3-3.1-3 4.3-.6z"/>',
    fill: '<path d="M2.5 9.5v3a1 1 0 0 0 1 1h9a1 1 0 0 0 1-1v-3"/><path d="M8 2v8M5 7l3 3 3-3"/>',
    refresh: '<path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9"/><path d="M13.5 2.2v3.2h-3.2"/>',
    back: '<path d="M10 3 5 8l5 5"/>',
    external: '<path d="M9 2.5h4.5V7M13.5 2.5l-6 6"/><path d="M12 9.5v3a1 1 0 0 1-1 1H3.5a1 1 0 0 1-1-1V5a1 1 0 0 1 1-1h3"/>',
    warning: '<path d="M8 2.2 14.3 13.5H1.7z"/><path d="M8 6.5v3M8 11.5v.2"/>',
    shield: '<path d="M8 1.8 13 3.7v4c0 3.1-2.1 5.3-5 6.5-2.9-1.2-5-3.4-5-6.5v-4z"/>',
    check: '<path d="M3 8.5l3 3 7-7"/>',
    wand: '<path d="M2.5 13.5l7.5-7.5M8.5 4.5l3 3"/><path d="M12 1.8v2.4M10.8 3h2.4M13.8 7.5v1.6M13 8.3h1.6"/>',
    passkey: '<circle cx="6" cy="5" r="2.5"/><path d="M1.5 13.5c.5-2.3 2.2-3.8 4.5-3.8.9 0 1.7.2 2.4.6"/><circle cx="12" cy="9.3" r="1.8"/><path d="M12 11.1v3.2M12 12.9h1.4"/>',
    close: '<path d="M4 4l8 8M12 4l-8 8"/>',
    signin: '<path d="M9.5 2.5h3a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1h-3"/><path d="M2 8h8M7 5l3 3-3 3"/>',
    clock: '<circle cx="8" cy="8" r="6"/><path d="M8 4.5V8l2.5 1.5"/>',
    link: '<path d="M6.5 9.5l3-3"/><path d="M7 4.5l1.3-1.3a2.6 2.6 0 0 1 3.7 3.7L10.7 8.2M9 11.5l-1.3 1.3A2.6 2.6 0 0 1 4 9.1l1.3-1.3"/>',
    other: '<rect x="2.5" y="2.5" width="11" height="11" rx="2"/>',
  };
  const parser = new DOMParser();
  function icon(name, size = 16) {
    const span = el("span", { class: "nx-icon", "aria-hidden": "true" });
    const svg = parser.parseFromString(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${Number(size)}" height="${Number(size)}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${PATHS[name] ?? PATHS.other}</svg>`,
      "image/svg+xml",
    ).documentElement;
    span.append(document.importNode(svg, true));
    return span;
  }

  // ---- item tiles: the site's icon, its first letter, or the item kind ----

  const iconCache = new Map();
  let iconsOn = false;
  api.storage.local.get("icons").then(({ icons }) => (iconsOn = Boolean(icons)), () => {});
  function hue(text) {
    let h = 0;
    for (const c of text) h = (h * 31 + c.codePointAt(0)) >>> 0;
    return swatches[h % swatches.length];
  }
  function tile(item, size = 32) {
    const box = el("span", { class: "tile", style: `--size:${size}px` });
    const kind = item.kind ?? "login";
    if (kind !== "login") {
      box.classList.add("kind");
      box.append(icon(kind, Math.round(size * 0.5)));
      return box;
    }
    const name = (item.name || item.host || "?").trim();
    const color = hue(name.toLowerCase());
    box.style.setProperty("--tint", color);
    box.append(el("span", { class: "letter" }, [...name][0]?.toUpperCase() ?? "?"));
    const host = item.host;
    if (iconsOn && host) {
      const show = (url) => {
        if (!url) return;
        box.classList.add("favicon");
        box.replaceChildren(el("img", { src: url, alt: "" }));
      };
      if (iconCache.has(host)) {
        const known = iconCache.get(host);
        if (known instanceof Promise) known.then(show);
        else show(known);
      } else {
        const p = api.runtime.sendMessage({ cmd: "icon", host }).then((r) => r?.url ?? null, () => null);
        iconCache.set(host, p);
        p.then((url) => {
          iconCache.set(host, url);
          show(url);
        });
      }
    }
    return box;
  }

  return { api, el, icon, tile, apply, setIcons: (on) => (iconsOn = on) };
})();
