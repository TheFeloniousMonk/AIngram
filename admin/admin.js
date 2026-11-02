// AIngram admin page. No framework, no build step, no third-party code.
// Everything shown from the store goes in as text (textContent), never as HTML:
// entries can hold text an agent read on the web.
"use strict";

const $ = (id) => document.getElementById(id);
const state = { me: null, provider: null, account: null, before: null, filter: {}, policyBody: "" };

// ------------------------------------------------------------------ helpers

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
function short(addr) { return addr ? addr.slice(0, 6) + "…" + addr.slice(-4) : ""; }
function when(ts) { return ts ? ts.replace("T", " ").slice(0, 16) + " UTC" : "never"; }

async function api(path, body) {
  const opts = body === undefined
    ? { credentials: "same-origin" }
    : { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body) };
  const r = await fetch(path, opts);
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty body */ }
  if (r.status === 401 && !path.includes("/login/")) { signedOut(); throw new Error("Signed out. Sign in again."); }
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}

async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = old; }, 1500);
  } catch (_) { button.textContent = "Select and copy"; }
}

// ------------------------------------------------------------------ wallets
// EIP-6963 lists every installed wallet; window.ethereum is the fallback.

const wallets = new Map();
window.addEventListener("eip6963:announceProvider", (e) => {
  const d = e.detail;
  if (d && d.info && d.provider) wallets.set(d.info.uuid, d);
  if (!$("signin").hidden) renderWallets();
});
window.dispatchEvent(new Event("eip6963:requestProvider"));

function walletList() {
  const list = [...wallets.values()];
  if (!list.length && window.ethereum) list.push({ info: { uuid: "injected", name: "Browser wallet", rdns: "injected" }, provider: window.ethereum });
  return list;
}

function remembered() { try { return localStorage.getItem("aingram.wallet"); } catch (_) { return null; } }
function remember(rdns) { try { localStorage.setItem("aingram.wallet", rdns); } catch (_) { /* ignore */ } }

async function connect(w) {
  const accounts = await w.provider.request({ method: "eth_requestAccounts" });
  if (!accounts || !accounts.length) throw new Error("The wallet shared no account.");
  state.provider = w.provider;
  state.account = accounts[0];
  remember(w.info.rdns);
  if (w.provider.on) w.provider.on("accountsChanged", (a) => { state.account = (a && a[0]) || null; });
  return state.account;
}

function toHex(text) {
  return "0x" + Array.from(new TextEncoder().encode(text), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sign(message) {
  return state.provider.request({ method: "personal_sign", params: [toHex(message), state.account] });
}

// The wallet that signs a change must be the admin wallet; check before asking it.
async function ensureAdminWallet() {
  const admin = state.me.address.toLowerCase();
  if (state.provider && state.account && state.account.toLowerCase() === admin) return;
  const list = walletList();
  if (!list.length) throw new Error("No browser wallet found. Install or unlock one, then reload.");
  const pick = list.find((w) => w.info.rdns === remembered()) || list[0];
  await connect(pick);
  if (state.account.toLowerCase() !== admin)
    throw new Error(`Switch your wallet to the admin account ${short(state.me.address)} and try again.`);
}

// ------------------------------------------------------------------ sign-in

function renderWallets() {
  const box = $("wallets");
  fill(box, );
  const list = walletList();
  if (!list.length) {
    box.append(h("p", { class: "muted" }, "No browser wallet found. Install one such as Rabby or MetaMask, unlock it, and reload this page."));
    return;
  }
  for (const w of list) {
    box.append(h("button", { class: "wallet", onclick: () => signIn(w) },
      w.info.icon ? h("img", { src: w.info.icon, alt: "" }) : null,
      `Sign in with ${w.info.name}`));
  }
}

async function signIn(w) {
  const err = $("signin-error");
  show(err, false);
  try {
    const account = await connect(w);
    const { message } = await api("/admin/api/login/challenge", { address: account });
    const signature = await sign(message);
    await api("/admin/api/login/verify", { message, signature });
    await start();
  } catch (e) {
    err.textContent = walletError(e);
    show(err, true);
  }
}

function walletError(e) {
  if (e && (e.code === 4001 || /reject|denied|cancel/i.test(e.message || ""))) return "You cancelled in the wallet. Nothing happened.";
  return (e && e.message) || String(e);
}

function signedOut() {
  state.me = null;
  show($("app"), false);
  show($("who"), false);
  show($("signin"), true);
  $("signin-host").textContent = location.host;
  renderWallets();
}

$("signout").addEventListener("click", async () => {
  try { await api("/admin/api/logout", {}); } catch (_) { /* already out */ }
  signedOut();
});

$("signout-all").addEventListener("click", async () => {
  try { await api("/admin/api/logout", { everywhere: true }); } catch (_) { /* already out */ }
  signedOut();
});

// ------------------------------------------------------------------ signed changes

function modal(title, body, actions) {
  $("modal-title").textContent = title;
  fill($("modal-body"), body);
  fill($("modal-actions"), ...actions);
  show($("modal"), true);
}
function closeModal() { show($("modal"), false); }

// Ask the server to prepare the command, let the wallet sign that exact text, confirm it.
// `expect`, if given, must accept the prepared action before anything is signed.
async function signed(request, title, expect) {
  let message;
  try {
    await ensureAdminWallet();
    let action;
    ({ message, action } = await api("/admin/api/actions/prepare", request));
    if (expect && !expect(action)) throw new Error("The server prepared something other than what you checked. Nothing was signed.");
  } catch (e) {
    modal(title, h("p", { class: "error" }, walletError(e)), [h("button", { onclick: closeModal }, "Close")]);
    return null;
  }
  modal(title, [
    h("p", {}, "Your wallet will show this message. Approve it there only if it says what you meant."),
    h("pre", { class: "message" }, message),
    h("p", { class: "muted", id: "sign-status" }, "Waiting for your wallet…"),
  ], [h("button", { class: "ghost", onclick: closeModal }, "Cancel")]);
  try {
    const signature = await sign(message);
    if ($("modal").hidden) return null;
    $("sign-status").textContent = "Checking the signature…";
    const result = await api("/admin/api/actions/confirm", { message, signature });
    closeModal();
    return result;
  } catch (e) {
    modal(title, h("p", { class: "error" }, walletError(e)), [h("button", { onclick: closeModal }, "Close")]);
    return null;
  }
}

// ------------------------------------------------------------------ app

async function start() {
  try { state.me = await api("/admin/api/me"); } catch (_) { signedOut(); return; }
  show($("signin"), false);
  show($("app"), true);
  show($("who"), true);
  $("who-addr").textContent = short(state.me.address);
  $("who-addr").title = state.me.address;
  $("mcp-url").textContent = state.me.mcp_url;
  show($("setup"), state.me.setup_needed);
  if (state.me.setup_needed) tab("policy"); else tab(current || "overview");
}

let current = null;
function tab(name) {
  current = name;
  for (const b of $("tabs").querySelectorAll("button")) b.classList.toggle("on", b.dataset.tab === name);
  for (const s of document.querySelectorAll(".tab")) show(s, s.id === `tab-${name}`);
  Promise.resolve(({ overview, memory, keys, policy, activity })[name]()).catch((e) => {
    if (state.me) modal("Something went wrong", h("p", { class: "error" }, e.message), [h("button", { onclick: closeModal }, "Close")]);
  });
}
$("tabs").addEventListener("click", (e) => { if (e.target.dataset.tab) tab(e.target.dataset.tab); });
document.addEventListener("click", (e) => {
  const t = e.target;
  if (t.dataset && t.dataset.goto) tab(t.dataset.goto);
  if (t.dataset && t.dataset.copy) copy($(t.dataset.copy).textContent, t);
});

async function refreshMe() {
  state.me = await api("/admin/api/me");
  show($("setup"), state.me.setup_needed);
}

// -- overview

async function overview() {
  await refreshMe();
  const m = state.me;
  const stat = (label, value) => h("div", { class: "card stat" }, h("div", { class: "muted" }, label), h("div", { class: "big" }, value));
  fill($("stats"), 
    stat("Entries by the brain", m.entries.brain || 0),
    stat("Entries by code", m.entries.code || 0),
    stat("Forgotten", m.redacted),
    stat("Active keys", m.active_keys),
    stat("Chain head", m.head.seq ? `#${m.head.seq}  ${m.head.id}` : "empty"),
    stat("Policy", m.policy ? m.policy.slice(0, 12) : "not approved"),
  );
}

$("verify").addEventListener("click", async () => {
  const out = $("verify-result");
  out.className = "muted";
  out.textContent = "Checking…";
  try {
    const { problems } = await api("/admin/api/verify", {});
    out.className = problems.length ? "error" : "ok";
    out.textContent = problems.length ? problems.join("\n") : "The chain verifies.";
  } catch (e) { out.className = "error"; out.textContent = e.message; }
});

// -- memory

async function memory() {
  const { subjects } = await api("/admin/api/subjects");
  const list = $("subject-list");
  fill(list, ...subjects.map((s) =>
    h("li", {}, h("button", { class: "link subject", onclick: () => loadEntries({ subject: s.subject }, s.subject) },
      s.subject, h("span", { class: "count" }, s.count)))));
  if (!list.children.length) list.append(h("li", { class: "muted" }, "Nothing written yet."));
  loadEntries(state.filter, $("entries-title").textContent);
}

$("all-entries").addEventListener("click", () => loadEntries({}, "Latest entries"));
$("search").addEventListener("submit", (e) => {
  e.preventDefault();
  const q = $("query").value.trim();
  if (q) loadEntries({ query: q }, `Search: ${q}`);
});
$("more").addEventListener("click", () => loadEntries(state.filter, $("entries-title").textContent, true));

async function loadEntries(filter, title, more) {
  state.filter = filter;
  $("entries-title").textContent = title || "Latest entries";
  const params = new URLSearchParams(filter);
  if (more && state.before) params.set("before", state.before);
  const list = $("entry-list");
  try {
    const data = await api(`/admin/api/entries?${params}`);
    const rows = data.entries.map((e) => h("li", {},
      h("button", { class: "entry" + (e.redacted ? " redacted" : ""), onclick: () => openEntry(e.id) },
        h("div", { class: "meta" }, h("span", { class: `voice ${e.voice}` }, e.voice), e.kind, " · ", e.subject,
          e.pinned ? " · pinned" : "", e.untrusted_ctx ? ` · outside text: ${e.untrusted_ctx}` : "",
          h("span", { class: "muted right" }, when(e.ts))),
        h("div", {}, e.redacted ? "Forgotten" : e.excerpt))));
    if (more) list.append(...rows); else fill(list, ...rows);
    if (!list.children.length) list.append(h("li", { class: "muted" }, "No entries."));
    state.before = data.next_before;
    show($("more"), data.next_before !== null);
  } catch (e) { fill(list, h("li", { class: "error" }, e.message)); }
}

async function openEntry(id) {
  const box = $("detail");
  show(box, true);
  fill(box, h("p", { class: "muted" }, "Loading…"));
  let e;
  try { e = await api(`/admin/api/entries/${encodeURIComponent(id)}`); }
  catch (err) { fill(box, h("p", { class: "error" }, err.message)); return; }
  const link = (x) => h("button", { class: "link mono", onclick: () => openEntry(x) }, x);
  const links = (label, xs) => xs && xs.length ? h("p", {}, h("span", { class: "muted" }, label + ": "), ...xs.flatMap((x) => [link(x), " "])) : null;
  fill(box, 
    h("div", { class: "row spread" }, h("h2", {}, e.subject), h("button", { class: "ghost", onclick: () => show(box, false) }, "Close")),
    h("p", { class: "meta" }, h("span", { class: `voice ${e.voice}` }, e.voice), `${e.kind} · #${e.seq} · ${when(e.ts)} · key ${e.key_id}`),
    h("p", { class: "mono muted small" }, e.id),
    e.untrusted_ctx ? h("p", { class: "warn" }, `Written with outside text in context (${e.untrusted_ctx}).`) : null,
    e.redacted
      ? h("div", { class: "forgotten" }, h("p", {}, `Forgotten ${when(e.redacted_at)}.`),
          e.redaction ? h("p", { class: "muted" }, `Reason (only you see this): ${e.redaction.reason}`) : null)
      : [h("p", { class: "excerpt" }, e.excerpt),
         e.keywords && e.keywords.length ? h("p", { class: "muted" }, e.keywords.join(", ")) : null,
         e.body ? h("pre", { class: "body" }, e.body) : null],
    links("Replaces", e.supersedes ? [e.supersedes] : []),
    links("Replaced by", e.superseded_by),
    links("Cites", e.refs),
    links("Cited by", e.cited_by),
    !e.redacted && e.kind !== "redaction" ? h("button", { class: "danger", onclick: () => forget(e) }, "Forget this entry…") : null,
  );
}

function forget(e) {
  const reason = h("input", { id: "forget-reason", maxlength: "500", placeholder: "Why? Only you will see this.", autocomplete: "off" });
  modal("Forget this entry", [
    h("p", {}, "Its content is erased for good. A marker stays in the chain, and the brain is told that something was forgotten, never what."),
    h("p", { class: "excerpt" }, e.excerpt),
    reason,
  ], [
    h("button", { class: "ghost", onclick: closeModal }, "Cancel"),
    h("button", { class: "danger", onclick: async () => {
      const result = await signed({ action: "redact", id: e.id, reason: reason.value }, "Forget this entry");
      if (!result) return;
      const flagged = result.flagged_for_review || [];
      modal("Forgotten", [
        h("p", {}, "The entry's content is gone."),
        flagged.length ? h("p", {}, "These entries replaced or cited it. Check whether they repeat what was forgotten:") : null,
        ...flagged.map((x) => h("button", { class: "link mono", onclick: () => { closeModal(); openEntry(x); } }, x)),
      ], [h("button", { onclick: closeModal }, "Done")]);
      memory();
      openEntry(e.id);
    } }, "Confirm in wallet"),
  ]);
  reason.focus();
}

// -- keys

async function keys() {
  const { keys: rows } = await api("/admin/api/keys");
  const body = $("key-rows");
  fill(body, ...rows.filter((k) => k.bearer).map((k) => h("tr", { class: k.revoked_at ? "revoked" : "" },
    h("td", { class: "mono" }, k.key_id), h("td", {}, k.voice), h("td", {}, k.label || ""),
    h("td", {}, when(k.last_used_at)), h("td", {}, k.revoked_at ? `revoked ${when(k.revoked_at)}` : "active"),
    h("td", { class: "actions" }, k.revoked_at ? null : [
      h("button", { class: "ghost", onclick: () => rotate(k) }, "Replace"),
      h("button", { class: "ghost danger", onclick: () => revoke(k) }, "Revoke"),
    ]))));
  if (!body.children.length) body.append(h("tr", {}, h("td", { colspan: "6", class: "muted" }, "No keys yet.")));
}

$("mint").addEventListener("submit", async (e) => {
  e.preventDefault();
  const result = await signed({ action: "keys.mint", voice: "code", label: $("mint-label").value }, "Create a code key");
  if (!result) return;
  $("mint-label").value = "";
  showSecret(result);
  keys();
});

async function revoke(k) {
  const result = await signed({ action: "keys.revoke", key_id: k.key_id }, `Revoke ${k.key_id}`);
  if (result) keys();
}

async function rotate(k) {
  const result = await signed({ action: "keys.rotate", key_id: k.key_id }, `Replace ${k.key_id}`);
  if (!result) return;
  showSecret(result);
  keys();
}

function showSecret(r) {
  const url = state.me.mcp_url;
  const cmd = `claude mcp add --transport http aingram ${url} --header "Authorization: Bearer ${r.secret}"`;
  const json = JSON.stringify({ mcpServers: { aingram: { type: "http", url, headers: { Authorization: `Bearer ${r.secret}` } } } }, null, 2);
  const block = (label, text) => {
    const pre = h("pre", { class: "secret" }, text);
    return [h("p", { class: "muted" }, label), pre, h("button", { class: "ghost", onclick: (e) => copy(text, e.target) }, "Copy")];
  };
  modal(`Key ${r.key_id} is ready`, [
    r.revoked ? h("p", {}, `${r.revoked} is revoked; agents using it must switch to this key.`) : null,
    h("p", { class: "warn" }, "This is the only time the secret is shown. It is not stored anywhere, so copy it now."),
    ...block("Secret", r.secret),
    ...block("Claude Code, in a terminal", cmd),
    ...block("Or in a project's .mcp.json", json),
  ], [h("button", { onclick: closeModal }, "I've saved it")]);
}

// -- policy

async function policy() {
  const data = await api("/admin/api/policy");
  const text = data.approved ? data.approved.body : data.draft;
  state.policyBody = data.approved ? data.approved.body : "";
  $("policy-state").textContent = data.approved
    ? `Approved policy ${data.approved.sha256.slice(0, 12)}. Edit it below, check the changes, then approve them in your wallet.`
    : "Nothing is approved yet. This is a starting draft: read it, adjust it, then approve it in your wallet.";
  if (!$("policy-text").dataset.dirty) $("policy-text").value = text;
  show($("policy-error"), false);
  show($("policy-diff"), false);
}

$("policy-text").addEventListener("input", () => { $("policy-text").dataset.dirty = "1"; });
$("policy-reset").addEventListener("click", () => { delete $("policy-text").dataset.dirty; policy(); });

async function checkPolicy(text) {
  const err = $("policy-error"), diff = $("policy-diff");
  show(err, false); show(diff, false);
  const r = await api("/admin/api/policy/check", { body: text });
  if (!r.valid) { err.textContent = r.error; show(err, true); return null; }
  if (r.unchanged) { err.textContent = "No changes from the approved policy."; show(err, true); return null; }
  fill(diff, ...r.diff.split("\n").map((line) =>
    h("span", { class: line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : "" }, line + "\n")));
  show(diff, Boolean(r.diff));
  return r;
}

$("policy-check").addEventListener("click", async () => {
  try { await checkPolicy($("policy-text").value); } catch (e) { $("policy-error").textContent = e.message; show($("policy-error"), true); }
});

$("policy-approve").addEventListener("click", async () => {
  // Approve exactly the text that was checked and shown, even if the box is edited meanwhile.
  const text = $("policy-text").value;
  let r;
  try { r = await checkPolicy(text); } catch (e) { $("policy-error").textContent = e.message; show($("policy-error"), true); return; }
  if (!r) return;
  const result = await signed({ action: "policy.approve", body: text }, "Approve this policy",
    (action) => action.action === "policy.approve" && action.sha256 === r.sha256);
  if (!result) return;
  delete $("policy-text").dataset.dirty;
  await refreshMe();
  policy();
});

// -- activity

async function activity() {
  const { log } = await api("/admin/api/log");
  fill($("log"), ...log.map((r) => h("li", { class: r.event },
    h("span", { class: "muted" }, when(r.at)), " ", h("strong", {}, r.event), " ",
    h("span", { class: "mono" }, JSON.stringify(r.action)), r.detail ? h("div", { class: "muted" }, r.detail) : null)));
  if (!$("log").children.length) $("log").append(h("li", { class: "muted" }, "No admin activity yet."));
}

start();
