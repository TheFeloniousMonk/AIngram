// Shared by the admin page and the grant page: DOM helpers and the browser wallet.
// No framework, no build step, no third-party code. Everything shown from the
// server goes in as text (textContent), never as HTML.
"use strict";

window.AIngramWallet = (() => {
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : v);
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid === null || kid === undefined || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  // Replace an element's children; nested lists are flattened and empty slots skipped.
  function fill(el, ...kids) {
    el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false)
      .map((k) => (k instanceof Node ? k : document.createTextNode(String(k)))));
  }

  function show(el, on) { el.hidden = !on; }

  // Feedback. kind is "ok", "err", "info" or "warn"; colour plus an icon, never colour alone.
  const ICONS = { ok: "✓", err: "!", info: "i", warn: "!" };
  function notice(kind, title, detail) {
    return h("div", { class: `notice ${kind}`, role: kind === "err" ? "alert" : "status" },
      h("span", { class: "icon", "aria-hidden": "true" }, ICONS[kind] || "i"),
      h("div", { class: "text" }, detail ? [h("strong", {}, title), detail] : title));
  }
  // Put a banner into a placeholder element (and show it), or clear it with kind = null.
  function say(el, kind, title, detail) {
    if (!kind) { fill(el); show(el, false); return; }
    fill(el, notice(kind, title, detail));
    show(el, true);
  }
  function toast(kind, title, detail) {
    let box = document.getElementById("toasts");
    if (!box) {
      box = h("div", { id: "toasts", class: "toasts", "aria-live": "polite" });
      document.body.append(box);
    }
    const t = notice(kind, title, detail);
    t.classList.add("toast");
    const close = () => t.remove();
    t.append(h("button", { class: "close", "aria-label": "Dismiss", onclick: close }, "×"));
    box.append(t);
    setTimeout(close, kind === "err" ? 10000 : 5000);
  }
  function short(addr) { return addr ? addr.slice(0, 6) + "…" + addr.slice(-4) : ""; }

  // EIP-6963 lists every installed wallet; window.ethereum is the fallback.
  const wallets = new Map();
  const listeners = [];
  const current = { provider: null, account: null };

  window.addEventListener("eip6963:announceProvider", (e) => {
    const d = e.detail;
    if (d && d.info && d.provider) wallets.set(d.info.uuid, d);
    listeners.forEach((fn) => fn());
  });
  window.dispatchEvent(new Event("eip6963:requestProvider"));

  function list() {
    const out = [...wallets.values()];
    if (!out.length && window.ethereum) out.push({ info: { uuid: "injected", name: "Browser wallet", rdns: "injected" }, provider: window.ethereum });
    return out;
  }

  function remembered() { try { return localStorage.getItem("aingram.wallet"); } catch (_) { return null; } }
  function remember(rdns) { try { localStorage.setItem("aingram.wallet", rdns); } catch (_) { /* ignore */ } }

  async function connect(w) {
    const accounts = await w.provider.request({ method: "eth_requestAccounts" });
    if (!accounts || !accounts.length) throw new Error("The wallet shared no account.");
    current.provider = w.provider;
    current.account = accounts[0];
    remember(w.info.rdns);
    if (w.provider.on) w.provider.on("accountsChanged", (a) => { current.account = (a && a[0]) || null; });
    return current.account;
  }

  // Connect the remembered wallet (or the only one) without asking which.
  async function connectDefault() {
    const all = list();
    if (!all.length) throw new Error("No browser wallet found. Install or unlock one, then reload.");
    return connect(all.find((w) => w.info.rdns === remembered()) || all[0]);
  }

  function toHex(text) {
    return "0x" + Array.from(new TextEncoder().encode(text), (b) => b.toString(16).padStart(2, "0")).join("");
  }

  // personal_sign over the exact UTF-8 text; the wallet shows it before signing.
  async function sign(message) {
    return current.provider.request({ method: "personal_sign", params: [toHex(message), current.account] });
  }

  function cancelled(e) {
    return Boolean(e && (e.code === 4001 || /reject|denied|cancel/i.test(e.message || "")));
  }

  function walletError(e) {
    if (cancelled(e)) return "You cancelled in the wallet. Nothing happened.";
    return (e && e.message) || String(e);
  }

  // A failed wallet step as a banner: cancelling is information, not an error.
  function walletNotice(e) {
    return cancelled(e) ? notice("info", "Cancelled", "You cancelled in the wallet. Nothing changed.")
      : notice("err", "That didn't work", walletError(e));
  }

  // One button per installed wallet, or a hint when there is none.
  function renderButtons(box, verb, onPick) {
    fill(box);
    const all = list();
    if (!all.length) {
      box.append(h("p", { class: "muted" }, "No browser wallet found. Install one such as Rabby or MetaMask, unlock it, and reload this page."));
      return;
    }
    for (const w of all) {
      box.append(h("button", { class: "wallet", onclick: () => onPick(w) },
        w.info.icon ? h("img", { src: w.info.icon, alt: "" }) : null, `${verb} with ${w.info.name}`));
    }
  }

  return { h, fill, show, short, list, connect, connectDefault, sign, walletError, walletNotice, cancelled,
           renderButtons, notice, say, toast,
           onChange: (fn) => listeners.push(fn), account: () => current.account,
           connected: () => Boolean(current.provider && current.account) };
})();
