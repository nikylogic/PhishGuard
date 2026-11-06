"use strict";
(() => {
  const { api, h, toast, ago } = PG;
  const $ = (id) => document.getElementById(id);

  for (const b of document.querySelectorAll(".tabs button")) {
    b.addEventListener("click", () => {
      for (const o of document.querySelectorAll(".tabs button")) o.setAttribute("aria-selected", o === b);
      for (const p of document.querySelectorAll(".tab-panel")) p.hidden = p.id !== `tab-${b.dataset.tab}`;
    });
  }

  async function loadSettings() {
    const s = await api("/api/settings");
    const sel = $("browser");
    sel.replaceChildren(h("option", { value: "" }, "Detect automatically"),
      ...s.browsers.map((b) => h("option", { value: b.path }, `${b.name}: ${b.path}`)));
    sel.value = s.browser_path || "";
    $("provider").value = s.llm_provider || "none";
    $("model").value = s.llm_model || "";
    $("key").value = s.llm_api_key || "";
  }
  async function save(body) {
    try { await api("/api/settings", { method: "POST", body }); toast("Saved.", "good"); }
    catch (e) { toast(e.message, "bad"); }
  }
  $("browser-form").addEventListener("submit", (e) => { e.preventDefault(); save({ browser_path: $("browser").value }); });
  $("llm-form").addEventListener("submit", (e) => {
    e.preventDefault();
    save({ llm_provider: $("provider").value, llm_model: $("model").value, llm_api_key: $("key").value });
  });

  async function loadUsers() {
    const { users } = await api("/api/users");
    $("users").replaceChildren(...users.map((u) => h("tr", {},
      h("td", {}, h("b", {}, u.username), h("div", { class: "muted" }, u.role)),
      h("td", { class: "muted" }, u.last_login ? `last in ${ago(u.last_login)}` : "never logged in"),
      h("td", {}, h("button", { class: "linkish", type: "button", onclick: () => del(u) }, "Remove")))));
  }
  async function del(u) {
    try { await api(`/api/users/${u.id}`, { method: "DELETE" }); toast(`${u.username} removed.`); loadUsers(); }
    catch (e) { toast(e.message, "bad"); }
  }
  $("user-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await api("/api/users", { method: "POST", body: { username: $("u-name").value, password: $("u-pw").value, role: $("u-role").value } });
      toast("Added.", "good");
      e.target.reset();
      loadUsers();
    } catch (err) { toast(err.message, "bad"); }
  });

  async function loadAudit() {
    const { items } = await api("/api/audit");
    $("audit").replaceChildren(...items.map((a) => h("tr", {},
      h("td", { class: "muted" }, ago(a.created_at)), h("td", {}, a.username || "launcher"),
      h("td", {}, a.action.replace(/_/g, " ")), h("td", { class: "url" }, a.detail || ""))));
  }
  loadSettings(); loadUsers(); loadAudit();
})();
