// AIngram admin page. No framework, no build step, no third-party code.
// Everything shown from the store goes in as text (textContent), never as HTML:
// entries can hold text an agent read on the web.
"use strict";

const $ = (id) => document.getElementById(id);
const state = { me: null, before: null, filter: {}, policyBody: "" };

// ------------------------------------------------------------------ helpers

const W = window.AIngramWallet;
const { h, fill, show, short } = W;
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

W.onChange(() => { if (!$("signin").hidden) renderWallets(); });

// The wallet that signs a change must be the admin wallet; check before asking it.
async function ensureAdminWallet() {
  const admin = state.me.address.toLowerCase();
  if (W.connected() && W.account().toLowerCase() === admin) return;
  await W.connectDefault();
  if (W.account().toLowerCase() !== admin)
    throw new Error(`Switch your wallet to the admin account ${short(state.me.address)} and try again.`);
}

// ------------------------------------------------------------------ sign-in

function renderWallets() {
  W.renderButtons($("wallets"), "Sign in", signIn);
}

async function signIn(w) {
  const err = $("signin-error");
  show(err, false);
  try {
    const account = await W.connect(w);
    const { message } = await api("/admin/api/login/challenge", { address: account });
    const signature = await W.sign(message);
    await api("/admin/api/login/verify", { message, signature });
    await start();
  } catch (e) {
    err.textContent = W.walletError(e);
    show(err, true);
  }
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
    modal(title, h("p", { class: "error" }, W.walletError(e)), [h("button", { onclick: closeModal }, "Close")]);
    return null;
  }
  modal(title, [
    h("p", {}, "Your wallet will show this message. Approve it there only if it says what you meant."),
    h("pre", { class: "message" }, message),
    h("p", { class: "muted", id: "sign-status" }, "Waiting for your wallet…"),
  ], [h("button", { class: "ghost", onclick: closeModal }, "Cancel")]);
  try {
    const signature = await W.sign(message);
    if ($("modal").hidden) return null;
    $("sign-status").textContent = "Checking the signature…";
    const result = await api("/admin/api/actions/confirm", { message, signature });
    closeModal();
    return result;
  } catch (e) {
    modal(title, h("p", { class: "error" }, W.walletError(e)), [h("button", { onclick: closeModal }, "Close")]);
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
  setupBanner();
  if (state.me.setup_needed) tab("policy"); else tab(current || "overview");
}

let current = null;
function tab(name) {
  current = name;
  for (const b of $("tabs").querySelectorAll("button")) b.classList.toggle("on", b.dataset.tab === name);
  for (const s of document.querySelectorAll(".tab")) show(s, s.id === `tab-${name}`);
  Promise.resolve(({ overview, memory, keys, policy, "import": importTab, activity })[name]()).catch((e) => {
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
  setupBanner();
}

function setupBanner() {
  const m = state.me;
  const text = m.policy_problem
    ? (m.setup_needed
      ? `Memory is off: the approved policy could not be loaded (${m.policy_problem}). Review it and approve a fixed version.`
      : `The latest policy approval was not applied (${m.policy_problem}). The previous policy is still in force.`)
    : "No policy is approved yet. Memory stays off until you review the policy and approve it.";
  $("setup-text").textContent = text;
  show($("setup"), m.setup_needed || Boolean(m.policy_problem));
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
    m.faded !== undefined ? stat("Faded (this week)", `${m.faded} (${m.faded_this_week})`) : null,
    stat("Active keys", m.active_keys),
    stat("Chain head", m.head.seq ? `#${m.head.seq}  ${m.head.id}` : "empty"),
    stat("Policy", m.policy ? m.policy.slice(0, 12) : "not approved"),
  );
  await backups();
}

// -- nightly backup

async function backups() {
  const { tokens } = await api("/admin/api/backups");
  fill($("backup-list"), tokens.map((t) => h("li", { class: "row spread" + (t.revoked_at ? " muted" : "") },
    h("span", {}, h("span", { class: "mono" }, t.token_id), ` ${t.label || ""} · `,
      t.revoked_at ? `revoked ${when(t.revoked_at)}` : `last backup ${when(t.last_used_at)}`),
    t.revoked_at ? null : h("button", { class: "ghost danger", onclick: async () => {
      if (await signed({ action: "backup.revoke", token_id: t.token_id }, `Revoke backup token ${t.token_id}`)) backups();
    } }, "Revoke"))));
  if (!tokens.length) $("backup-list").append(h("li", { class: "muted" }, "No backup is set up yet."));
}

$("backup-mint").addEventListener("submit", async (e) => {
  e.preventDefault();
  const result = await signed({ action: "backup.mint", label: $("backup-label").value }, "Create a backup token");
  if (!result) return;
  $("backup-label").value = "";
  const info = await api("/admin/api/backups");
  showBackupSetup(result, info);
  backups();
});

function showBackupSetup(r, info) {
  const block = (label, text) => {
    const pre = h("pre", { class: "secret" }, text);
    return [h("p", { class: "muted" }, label), pre, h("button", { class: "ghost", onclick: (e) => copy(text, e.target) }, "Copy")];
  };
  const cmd = `python aingram_backup.py install --url ${info.public_url} --token ${r.secret} --admin ${info.admin_address}`;
  modal(`Backup token ${r.token_id} is ready`, [
    h("p", { class: "warn" }, "This is the only time the token is shown. Use it for one of the two setups below."),
    h("h2", {}, "On your computer"),
    h("p", {}, "Needs Python and git. In a copy of AIngram, run pip install -r requirements-backup.txt, then this once. It makes a backup folder in your home folder, checks the first backup, and schedules one every night; if a check ever fails, a warning pops up."),
    ...block("Command", cmd),
    h("h2", {}, "Or on GitHub, with no install"),
    h("p", {}, "Make a new private repository. Add the file backup/aingram-backup.yml from AIngram as .github/workflows/aingram-backup.yml, then under Settings, Secrets and variables, Actions, add these. Run the workflow once from the Actions tab. If a check ever fails, GitHub emails you."),
    ...block("Secret AINGRAM_BACKUP_TOKEN", r.secret),
    ...block("Variable AINGRAM_BACKUP_URL", info.public_url),
    ...block("Variable AINGRAM_BACKUP_ADMIN", info.admin_address),
  ], [h("button", { onclick: closeModal }, "I've saved it")]);
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
$("faded-entries").addEventListener("click", loadFaded);

function isFaded(e) {
  return !e.redacted && typeof e.salience === "number" && state.me && state.me.fade_below !== undefined
    && e.salience < state.me.fade_below;
}

function entryRow(e, extra) {
  return h("li", {},
    h("button", { class: "entry" + (e.redacted ? " redacted" : "") + (isFaded(e) ? " faded" : ""), onclick: () => openEntry(e.id) },
      h("div", { class: "meta" }, h("span", { class: `voice ${e.voice}` }, e.voice), e.kind, " · ", e.subject,
        e.pinned ? " · pinned" : "", e.untrusted_ctx ? ` · outside text: ${e.untrusted_ctx}` : "",
        isFaded(e) ? " · faded" : "", h("span", { class: "muted right" }, extra || when(e.ts))),
      h("div", {}, e.redacted ? "Forgotten" : e.excerpt)));
}

// Entries that fell below the fade line, most recent first: what to look at when tuning half-lives.
async function loadFaded() {
  state.filter = {};
  const list = $("entry-list");
  show($("more"), false);
  try {
    const data = await api("/admin/api/faded");
    $("entries-title").textContent = `Faded: ${data.total} in all, ${data.this_week} this week`;
    fill(list, data.entries.map((e) => entryRow(e, `faded ${when(e.faded_at)}`)));
    if (!list.children.length) list.append(h("li", { class: "muted" }, "Nothing has faded."));
  } catch (e) { fill(list, h("li", { class: "error" }, e.message)); }
}
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
    const rows = data.entries.map((e) => entryRow(e));
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
    typeof e.salience === "number"
      ? h("p", { class: "muted small" }, e.pinned ? "Pinned: never fades." : `Salience ${e.salience}${isFaded(e) ? " (faded: out of the tail, low in search)" : ""}`)
      : null,
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
  // Bearer keys (code) and the brain's connector grants; the admin wallet's own row is not a credential.
  const shown = rows.filter((k) => k.bearer || k.voice === "brain");
  const imported = (k) => k.key_id.startsWith("k_brain_imp_");  // records an import; never a credential
  fill(body, ...shown.map((k) => h("tr", { class: k.revoked_at ? "revoked" : "" },
    h("td", { class: "mono" }, k.key_id),
    h("td", {}, k.bearer ? k.voice : imported(k) ? `${k.voice} (import)` : `${k.voice} (connector)`),
    h("td", {}, k.label || ""),
    h("td", {}, when(k.last_used_at)),
    h("td", {}, imported(k) ? "not a credential" : k.revoked_at ? `revoked ${when(k.revoked_at)}` : "active"),
    h("td", { class: "actions" }, k.revoked_at || imported(k) ? null : [
      k.bearer ? h("button", { class: "ghost", onclick: () => rotate(k) }, "Replace") : null,
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
  state.policy = data;
  state.policyBody = data.approved ? data.approved.body : null;
  if (!$("policy-text").dataset.dirty) $("policy-text").value = text;
  show($("policy-error"), false);
  show($("policy-diff"), false);
  policyStatus();
}

// What the page leads with: whether a policy is in force, and whether there is anything to approve.
function policyStatus() {
  const data = state.policy;
  if (!data) return;
  const edited = state.policyBody !== null && $("policy-text").value !== state.policyBody;
  const status = $("policy-status"), approve = $("policy-approve");
  if (data.approved && !edited) {
    status.className = "status ok";
    fill(status, h("strong", {}, "✓ This policy is in force."),
      ` Approved ${data.approved.approved_at ? when(data.approved.approved_at) : ""} as ${data.approved.sha256.slice(0, 12)}.`);
    $("policy-state").textContent = "To change it, edit the text below; you'll be able to review the changes and approve them in your wallet.";
    approve.disabled = true;
    approve.textContent = "Nothing to approve";
  } else if (data.approved) {
    status.className = "status pending";
    fill(status, h("strong", {}, "Unapproved changes."),
      ` The policy in force is still ${data.approved.sha256.slice(0, 12)}. Check the changes, then approve them in your wallet, or discard them.`);
    $("policy-state").textContent = "";
    approve.disabled = false;
    approve.textContent = "Approve changes in wallet";
  } else {
    status.className = "status pending";
    fill(status, h("strong", {}, "No policy is in force."),
      state.me && state.me.policy_problem
        ? " The approved policy below no longer loads. Fix what the banner names, then approve it in your wallet."
        : " Memory is off. Read this starting draft, adjust it, then approve it in your wallet.");
    $("policy-state").textContent = "";
    approve.disabled = false;
    approve.textContent = "Approve in wallet";
  }
}

$("policy-text").addEventListener("input", () => { $("policy-text").dataset.dirty = "1"; policyStatus(); });
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

// -- import

let importText = null;

function importTab() {
  if (state.me && state.me.setup_needed) {
    $("import-error").textContent = "Approve a policy first: imports are checked against it.";
    show($("import-error"), true);
  }
}

$("import-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  show($("import-error"), false);
  show($("import-preview"), false);
  importText = null;
  if (!file) return;
  try {
    const text = await file.text();
    const r = await api("/admin/api/import/check", { body: text });
    importText = text;
    renderImport(r, file.name);
  } catch (err) { $("import-error").textContent = err.message; show($("import-error"), true); }
});

function renderImport(r, name) {
  const s = r.summary;
  $("import-headline").textContent = r.valid
    ? `${name}: ${s.entries} entries, all of them check out.`
    : `${name}: ${r.problem_count} problem(s). Nothing can be imported until the file is fixed.`;
  const stat = (label, value) => h("div", { class: "card stat" }, h("div", { class: "muted" }, label), h("div", { class: "big" }, value));
  const list = (obj) => Object.entries(obj).slice(0, 8).map(([k, v]) => `${k} ×${v}`).join(", ") || "none";
  fill($("import-stats"),
    stat("Entries", s.entries), stat("Pinned to the core", s.pinned),
    stat("With outside text", s.outside_text),
    stat("Dated", s.dated ? `${s.dated[0]} to ${s.dated[1]}` : "none"),
    h("div", { class: "card" }, h("div", { class: "muted" }, "Subjects"), h("div", {}, list(s.subjects))),
    h("div", { class: "card" }, h("div", { class: "muted" }, "Kinds"), h("div", {}, list(s.kinds))));
  fill($("import-problems"), r.problems.map((p) => h("li", { class: "error" }, p)),
    r.problem_count > r.problems.length ? h("li", { class: "muted" }, `and ${r.problem_count - r.problems.length} more`) : null);
  show($("import-apply"), r.valid);
  $("import-apply").dataset.sha = r.sha256 || "";
  $("import-apply").dataset.count = String(s.entries);
  show($("import-preview"), true);
}

$("import-apply").addEventListener("click", async () => {
  const sha = $("import-apply").dataset.sha, count = Number($("import-apply").dataset.count);
  const result = await signed({ action: "import.apply", body: importText }, `Import ${count} entries`,
    (action) => action.action === "import.apply" && action.sha256 === sha && action.entries === count);
  if (!result) return;
  show($("import-apply"), false);
  $("import-headline").textContent = `Imported ${result.imported} entries. They are in Memory now, written as the brain.`;
  $("import-file").value = "";
  importText = null;
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
