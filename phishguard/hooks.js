// PhishGuard sandbox watcher.
// Injected into every frame of the sandbox browser BEFORE any page script runs.
// It never blocks the page; it only reports which sensitive browser features the
// page touches. Reports go to a Python binding whose name is random per session.
(() => {
  const BINDING = "__PG_BINDING__";
  const send = (o) => {
    try {
      const f = window[BINDING];
      if (typeof f === "function") f(JSON.stringify(o));
    } catch (e) { /* never break the page */ }
  };
  const seen = new Set();
  const once = (key, o) => { if (!seen.has(key)) { seen.add(key); send(o); } };
  const fp = (k) => once("fp:" + k, { t: "fp", k });

  const wrap = (obj, prop, before) => {
    try {
      if (!obj) return;
      const orig = obj[prop];
      if (typeof orig !== "function") return;
      const w = function (...args) {
        try { before.apply(this, args); } catch (e) {}
        return orig.apply(this, args);
      };
      Object.defineProperty(w, "name", { value: orig.name });
      w.toString = () => Function.prototype.toString.call(orig);
      obj[prop] = w;
    } catch (e) {}
  };
  const wrapCtor = (holder, name, cb) => {
    try {
      const C = holder[name];
      if (typeof C !== "function") return;
      holder[name] = new Proxy(C, {
        construct(t, a, nt) { try { cb(a); } catch (e) {} return Reflect.construct(t, a, nt); },
        apply(t, self, a) { try { cb(a); } catch (e) {} return Reflect.apply(t, self, a); },
      });
    } catch (e) {}
  };
  const wrapGetter = (proto, prop, cb) => {
    try {
      const d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.get) return;
      Object.defineProperty(proto, prop, {
        ...d, get() { try { cb(); } catch (e) {} return d.get.call(this); },
      });
    } catch (e) {}
  };

  // --- fingerprinting ---------------------------------------------------------
  if (window.HTMLCanvasElement) {
    wrap(HTMLCanvasElement.prototype, "toDataURL", () => fp("canvas"));
    wrap(HTMLCanvasElement.prototype, "toBlob", () => fp("canvas"));
  }
  if (window.CanvasRenderingContext2D) {
    wrap(CanvasRenderingContext2D.prototype, "getImageData", () => fp("canvas"));
    let measures = 0;
    wrap(CanvasRenderingContext2D.prototype, "measureText", () => { if (++measures > 40) fp("fonts"); });
  }
  if (window.FontFaceSet) {
    let checks = 0;
    wrap(FontFaceSet.prototype, "check", () => { if (++checks > 20) fp("fonts"); });
  }
  for (const G of [window.WebGLRenderingContext, window.WebGL2RenderingContext]) {
    if (!G) continue;
    wrap(G.prototype, "getParameter", (p) => { if (p === 37445 || p === 37446) fp("webgl"); });
    wrap(G.prototype, "getExtension", (n) => { if (n === "WEBGL_debug_renderer_info") fp("webgl"); });
  }
  for (const n of ["AudioContext", "OfflineAudioContext", "webkitAudioContext", "webkitOfflineAudioContext"]) {
    wrapCtor(window, n, () => fp("audio"));
  }
  if (window.Navigator && Navigator.prototype.getBattery) {
    wrap(Navigator.prototype, "getBattery", () => fp("battery"));
  }
  // Reading several device facts together is a profiling pattern; one alone is normal.
  const hw = new Set();
  for (const p of ["hardwareConcurrency", "deviceMemory", "plugins", "mimeTypes", "maxTouchPoints"]) {
    wrapGetter(Navigator.prototype, p, () => { hw.add(p); if (hw.size >= 3) fp("hardware"); });
  }
  if (window.MediaDevices) {
    wrap(MediaDevices.prototype, "enumerateDevices", () => fp("devices"));
  }
  for (const n of ["RTCPeerConnection", "webkitRTCPeerConnection"]) {
    wrapCtor(window, n, () => once("webrtc", { t: "webrtc" }));
  }

  // --- clipboard (ClickFix) ---------------------------------------------------
  if (window.Clipboard) {
    wrap(Clipboard.prototype, "writeText", (txt) => send({ t: "clipboard", text: String(txt).slice(0, 2000) }));
    wrap(Clipboard.prototype, "write", () => send({ t: "clipboard", text: "(binary clipboard write)" }));
  }
  wrap(Document.prototype, "execCommand", (cmd) => {
    if (String(cmd).toLowerCase() === "copy") {
      send({ t: "clipboard", text: String(document.getSelection() || "").slice(0, 2000) });
    }
  });
  if (window.DataTransfer) {
    wrap(DataTransfer.prototype, "setData", (_type, data) => send({ t: "clipboard", text: String(data).slice(0, 2000) }));
  }

  // --- permissions, fullscreen and other browser abuse ------------------------
  if (window.Notification) wrap(Notification, "requestPermission", () => once("perm:notifications", { t: "perm", k: "notifications" }));
  if (window.PushManager) wrap(PushManager.prototype, "subscribe", () => once("perm:push", { t: "perm", k: "push" }));
  if (window.Geolocation) {
    wrap(Geolocation.prototype, "getCurrentPosition", () => once("perm:location", { t: "perm", k: "location" }));
    wrap(Geolocation.prototype, "watchPosition", () => once("perm:location", { t: "perm", k: "location" }));
  }
  if (window.MediaDevices) wrap(MediaDevices.prototype, "getUserMedia", () => once("perm:camera", { t: "perm", k: "camera" }));
  wrap(Element.prototype, "requestFullscreen", () => once("fullscreen", { t: "fullscreen" }));
  wrap(Element.prototype, "webkitRequestFullscreen", () => once("fullscreen", { t: "fullscreen" }));
  if (window.Keyboard) wrap(Keyboard.prototype, "lock", () => once("keylock", { t: "keylock" }));
  wrap(EventTarget.prototype, "addEventListener", (type) => {
    if (type === "beforeunload") once("unload_trap", { t: "unload_trap" });
  });
  wrap(window, "open", (url) => send({ t: "popup", url: String(url || "").slice(0, 500) }));

  // --- crypto mining and obfuscation signals ------------------------------------
  if (window.WebAssembly) {
    for (const n of ["instantiate", "instantiateStreaming", "compile", "compileStreaming"]) {
      wrap(WebAssembly, n, () => once("wasm", { t: "wasm" }));
    }
    wrapCtor(WebAssembly, "Module", () => once("wasm", { t: "wasm" }));
  }
  let evals = 0;
  wrap(window, "eval", (src) => {
    // Playwright delivers binding replies through eval; those are ours, not the page's.
    if (String(src).includes("__playwright")) return;
    if (++evals === 3) send({ t: "eval", n: evals });
  });
  let bigAtob = 0;
  wrap(window, "atob", (s) => { if (String(s).length > 500 && ++bigAtob === 1) send({ t: "atob", n: String(s).length }); });
})();
