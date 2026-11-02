// Copy buttons on prompts, the Rabby/MetaMask switcher, and the folding sidebar on phones.
// No third-party code.
document.documentElement.classList.add("js");

const navBox = document.querySelector(".side-wrap");
if (navBox) {
  const toggle = navBox.querySelector(".side-toggle");
  toggle.addEventListener("click", () => {
    const open = navBox.classList.toggle("nav-open");
    toggle.setAttribute("aria-expanded", String(open));
    toggle.lastElementChild.textContent = open ? "Close ▴" : "Open ▾";
  });
}

document.querySelectorAll(".prompt").forEach((p) => {
  const btn = p.querySelector("button");
  const text = p.querySelector(".say").innerText.trim();
  btn.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(text); btn.textContent = "✓ Copied"; btn.classList.add("copied"); }
    catch (_) { btn.textContent = "Select the text to copy"; }
    setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 2000);
  });
});

document.querySelectorAll(".choose").forEach((c) => {
  const pick = (w) => {
    c.querySelectorAll("button").forEach((b) => b.classList.toggle("on", b.dataset.w === w));
    document.querySelectorAll("[data-for]").forEach((el) => { el.hidden = el.dataset.for !== w; });
    try { localStorage.setItem("aingram.docs.wallet", w); } catch (_) { /* ignore */ }
  };
  c.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => pick(b.dataset.w)));
  let saved = null;
  try { saved = localStorage.getItem("aingram.docs.wallet"); } catch (_) { /* ignore */ }
  pick(saved || c.querySelector("button").dataset.w);
});
