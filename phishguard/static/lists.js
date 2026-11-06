"use strict";
(() => {
  const { api, h, toast, ago } = PG;
  const $ = (id) => document.getElementById(id);

  async function load() {
    const { items } = await api("/api/lists");
    for (const kind of ["allow", "block"]) {
      const mine = items.filter((i) => i.kind === kind);
      $(kind).replaceChildren(...(mine.length ? mine.map((i) => h("tr", {},
        h("td", { class: "url" }, i.domain, i.note ? h("div", { class: "muted" }, i.note) : null),
        h("td", { class: "muted" }, i.added_by ? `${i.added_by}, ${ago(i.created_at)}` : ago(i.created_at)),
        h("td", {}, h("button", { class: "linkish", type: "button", onclick: () => remove(i) }, "Remove"))))
        : [h("tr", {}, h("td", { class: "empty" }, "Nothing here yet."))]));
    }
  }
  async function remove(i) {
    await api(`/api/lists/${i.id}`, { method: "DELETE" });
    toast(`${i.domain} removed.`);
    load();
  }
  for (const kind of ["allow", "block"]) {
    $(`add-${kind}`).addEventListener("submit", async (e) => {
      e.preventDefault();
      const input = $(`${kind}-dom`);
      try {
        const r = await api("/api/lists", { method: "POST", body: { domain: input.value, kind } });
        toast(`${r.domain} added.`, "good");
        input.value = "";
        load();
      } catch (err) { toast(err.message, "bad"); }
    });
  }
  load();
})();
