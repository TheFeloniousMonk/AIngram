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

function fail(title, detail) {
  W.say($("error"), "err", title, detail);
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
    fail("This approval link can't be used", e.message);
  }
}

function render() {
  if (!$("request").hidden) W.renderButtons($("wallets"), "Approve", approve);
}
W.onChange(render);

async function approve(w) {
  W.say($("error"), null);
  try {
    const account = await W.connect(w);
    const { message } = await api("/oauth/api/challenge", { r: sealed, address: account });
    $("message").textContent = message;
    W.show($("request"), false);
    W.show($("signing"), true);
    W.say($("status"), "info", "Waiting for your wallet…");
    const signature = await W.sign(message);
    W.say($("status"), "info", "Checking the signature…");
    const { redirect } = await api("/oauth/api/approve", { r: sealed, message, signature });
    W.say($("status"), "ok", "Approved", "The connector now has the brain voice. Taking you back to it…");
    setTimeout(() => location.assign(redirect), 1200);
  } catch (e) {
    W.show($("signing"), false);
    W.show($("request"), true);
    W.fill($("error"), W.walletNotice(e));
    W.show($("error"), true);
  }
}

$("deny").addEventListener("click", async () => {
  try {
    const { redirect } = await api("/oauth/api/deny", { r: sealed });
    W.show($("request"), false);
    W.say($("error"), "info", "Not connected", "Nothing was granted. Taking you back to the connector…");
    setTimeout(() => location.assign(redirect), 1200);
  } catch (e) { fail("Couldn't decline", e.message); }
});

load();
