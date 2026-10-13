// Fixture JS: deliberately exposes a small client-side API surface.
(function () {
  async function loadFeatured() {
    const res = await fetch("/api/products?featured=true");
    if (!res.ok) return;
    const items = await res.json();
    const el = document.getElementById("featured");
    if (el) el.textContent = items.length + " featured widgets";
  }

  async function loadRows(page) {
    const res = await fetch("/api/products?page=" + encodeURIComponent(page || 1));
    if (!res.ok) return;
    const items = await res.json();
    const tb = document.getElementById("rows");
    if (!tb) return;
    tb.innerHTML = items
      .map((p) => "<tr><td>" + p.name + "</td><td>" + p.price + "</td></tr>")
      .join("");
  }

  async function search(q) {
    const res = await fetch("/api/search?q=" + encodeURIComponent(q));
    return res.json();
  }

  const params = new URLSearchParams(location.search);
  if (document.getElementById("rows")) loadRows(params.get("page") || 1);
  if (document.getElementById("featured")) loadFeatured();
  window.__fixtureSearch = search;
})();
