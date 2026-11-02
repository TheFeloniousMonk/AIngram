// The approval page a connector (claude.ai) opens to be granted the brain voice.
// The admin wallet signs one Sign-In with Ethereum message naming this server,
// the voice, the connector and this exact request; the server then sends the
// browser back to the connector with a one-time code.
"use strict";

const W = window.AIngramWallet;
const $ = (id) => document.getElementById(id);
const sealed = new URLSearchParams(location.search).get("r") || "";

async function api(path, body) {
  const r = await fetch(path, { method: "POST", credentials: "omit",
    headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty body */ }
  if (!r.ok) throw new Error(data.error || `Request failed (${r.status})`);
  return data;
}

function fail(message) {
  $("error").textContent = message;
  W.show($("error"), true);
}

async function load() {
  try {
    const about = await api("/oauth/api/describe", { r: sealed });
    $("client").textContent = about.client_name;
    $("voice").textContent = about.voice;
    $("server").textContent = about.server;
    $("redirect-host").textContent = about.redirect_host;
    const mins = Math.floor(about.age_seconds / 60);
    $("age").textContent = mins < 1 ? "less than a minute ago" : `${mins} minute${mins === 1 ? "" : "s"} ago`;
    W.show($("loading"), false);
    W.show($("request"), true);
    render();
  } catch (e) {
    W.show($("loading"), false);
    fail(e.message);
  }
}

function render() {
  if (!$("request").hidden) W.renderButtons($("wallets"), "Approve", approve);
}
W.onChange(render);

async function approve(w) {
  W.show($("error"), false);
  try {
    const account = await W.connect(w);
    const { message } = await api("/oauth/api/challenge", { r: sealed, address: account });
    $("message").textContent = message;
    W.show($("request"), false);
    W.show($("signing"), true);
    const signature = await W.sign(message);
    $("status").textContent = "Checking the signature…";
    const { redirect } = await api("/oauth/api/approve", { r: sealed, message, signature });
    $("status").textContent = "Approved. Returning to the connector…";
    location.assign(redirect);
  } catch (e) {
    W.show($("signing"), false);
    W.show($("request"), true);
    fail(W.walletError(e));
  }
}

$("deny").addEventListener("click", async () => {
  try {
    const { redirect } = await api("/oauth/api/deny", { r: sealed });
    location.assign(redirect);
  } catch (e) { fail(e.message); }
});

load();
