/* LeakLens frontend checks (node, no dependencies).
   1. node --check is run by the pytest wrapper, not here.
   2. Every inline handler referenced in index.html must resolve to a defined
      function (no dead buttons).
   3. No mock/demo leftovers may remain in the production UI.
   4. Render smoke test with stubbed DOM + mocked API responses.
*/
"use strict";
const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..", "..");
const HTML = fs.readFileSync(path.join(ROOT, "leaklens", "index.html"), "utf8");
const CLIENT = fs.readFileSync(path.join(ROOT, "leaklens", "api-client.js"), "utf8");
const inline = HTML.split("<script>")[1].split("</script>")[0];

let failures = 0;
function check(name, cond, detail) {
  if (cond) { console.log("ok  - " + name); }
  else { failures++; console.log("FAIL- " + name + (detail ? " :: " + detail : "")); }
}

/* ---- 2. handler existence ---- */
const BUILTINS = new Set([
  "if", "for", "while", "switch", "catch", "function", "return",
  "confirm", "setTimeout", "setInterval", "clearInterval", "fetch",
  "scrollTo", "encodeURIComponent", "JSON", "Object", "Array", "Math", "Number",
  "String", "isNaN", "URL", "FormData", "AbortController",
]);
const defined = new Set();
for (const m of inline.matchAll(/(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g)) defined.add(m[1]);
for (const m of inline.matchAll(/(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/g)) defined.add(m[1]);
for (const m of CLIENT.matchAll(/([A-Za-z_$][\w$]*)\s*:\s*function/g)) defined.add(m[1]);
const handlerAttrs = ["onclick", "onchange", "onkeydown", "onkeyup", "oninput", "ondrop", "ondragover", "ondragleave"];
const missing = new Set();
const attrRe = new RegExp("\\b(?:" + handlerAttrs.join("|") + ")\\s*=\\s*\"([^\"]*)\"", "g");
let am;
while ((am = attrRe.exec(HTML)) !== null) {
  const code = am[1];
  for (const cm of code.matchAll(/([A-Za-z_$][\w$]*)\s*\(/g)) {
    const fn = cm[1];
    if (BUILTINS.has(fn)) continue;
    if (fn === "S" || fn === "document" || fn === "window" || fn === "navigator" || fn === "event" || fn === "this") continue;
    // method calls on objects (x.y(), el.click()) — resolve root object instead
    const before = code.slice(0, cm.index).replace(/\s+$/, "");
    if (before.endsWith(".")) continue;
    if (!defined.has(fn)) missing.add(fn + "  (in: " + code.slice(0, 80) + ")");
  }
}
check("all inline handlers resolve", missing.size === 0, [...missing].join(" | "));

/* ---- 3. mock purge ---- */
const BANNED = [
  "Maya Chen", "Signed in as", "24,821", "payments-api", "customer-dashboard",
  "mobile-backend", "ai-inference-service", "FND-", "const PJ=", "const F=",
  "const SC=", "const ACT=", "bench()", "Folder picker is simulated",
  "342 files", "14 findings", "AK_EXAMPLE_SYNTHETIC",
];
const foundBanned = BANNED.filter((t) => HTML.includes(t));
check("no mock/demo leftovers in UI", foundBanned.length === 0, foundBanned.join(", "));

/* ---- 4. render smoke test ---- */
function makeDom() {
  const byId = {};
  function el(id) {
    if (!byId[id]) {
      byId[id] = {
        id, innerHTML: "", value: "", checked: false, files: [],
        style: {}, dataset: {},
        click() {}, remove() {}, focus() {},
        classList: { toggle() {}, add() {}, remove() {} },
        append() {}, appendChild() {}, setAttribute() {},
        querySelectorAll() { return []; },
      };
    }
    return byId[id];
  }
  const listeners = {};
  return {
    _byId: byId,
    querySelector(s) {
      if (s[0] === "#") return el(s.slice(1));
      return el("__q__" + s);
    },
    getElementById(id) { return el(id); },
    createElement() {
      return { innerHTML: "", textContent: "", className: "", style: {},
        click() {}, remove() {}, append() {}, appendChild() {}, setAttribute() {} };
    },
    addEventListener(t, fn) { (listeners[t] = listeners[t] || []).push(fn); },
    body: { append() {}, appendChild() {} },
  };
}

const store = {};
const localStorageStub = {
  getItem: (k) => (k in store ? store[k] : null),
  setItem: (k, v) => { store[k] = String(v); },
  removeItem: (k) => { delete store[k]; },
};

function makeFetch(routes) {
  return async (url, opts) => {
    const path = String(url).replace(/^https?:\/\/[^/]+/, "");
    const entry = routes[path] || routes[path.split("?")[0] + "?*"];
    if (!entry) {
      return { ok: false, status: 404, headers: { get: () => "application/json" },
        json: async () => ({ detail: "No mock route for " + path }), text: async () => "" };
    }
    const [status, body] = entry;
    return { ok: status < 400, status, headers: { get: (h) => (h.toLowerCase() === "content-type" ? "application/json" : null) },
      json: async () => body, text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
      blob: async () => Buffer.from("x"), };
  };
}

async function runSmoke() {
  const document = makeDom();
  const sandbox = {
    document,
    window: {},
    localStorage: localStorageStub,
    navigator: {},
    AbortController: globalThis.AbortController,
    FormData: globalThis.FormData,
    URL: globalThis.URL,
    scrollTo() {},
    setTimeout: globalThis.setTimeout,
    clearTimeout: globalThis.clearTimeout,
    setInterval: globalThis.setInterval,
    clearInterval: globalThis.clearInterval,
    confirm: () => false,
    fetch: makeFetch({
      "/api/auth/status": [200, { setup_required: false }],
      "/api/auth/login": [200, { token: "tok", username: "u", expires_at: "x" }],
      "/api/auth/me": [200, { id: "1", username: "u" }],
      "/api/dashboard": [200, { projects: 0, scans: 0, findings: 0, high: 0, open: 0,
        severity: {}, recent_scans: [], recent_activity: [] }],
      "/api/projects": [200, []],
      "/api/findings?*": [200, []],
      "/api/activity": [200, []],
      "/api/settings": [200, {}],
      "/api/reports": [200, []],
      "/api/benchmarks": [200, { runs: [], latest: null, model_test_metrics: {}, model_comparison: {} }],
    }),
    console,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  const vm = require("vm");
  vm.createContext(sandbox);
  vm.runInContext(CLIENT, sandbox, { filename: "api-client.js" });
  // stub S inputs used by boot->login->dashboard path
  vm.runInContext(inline, sandbox, { filename: "index-inline.js" });
  await new Promise((r) => setTimeout(r, 50));
  const rootHtml = document._byId.root.innerHTML;
  check("boot renders login form when logged out",
    /id="lu"/.test(rootHtml) && /id="lp"/.test(rootHtml), rootHtml.slice(0, 120));

  // simulate login
  document.querySelector("#lu").value = "u";
  document.querySelector("#lp").value = "p";
  try {
    await sandbox.doLogin();
  } catch (e) { console.log("doLogin threw:", e.message); }
  await new Promise((r) => setTimeout(r, 50));
  const afterHtml = document._byId.root.innerHTML;
  const dashHtml = document._byId.root.innerHTML;
  check("dashboard renders after login", /Security Overview/.test(dashHtml), dashHtml.slice(0, 160));
  check("dashboard shows real zero-state, not fake counts",
    /No findings yet|No scans yet|No activity/.test(dashHtml), dashHtml.slice(0, 400));
}

runSmoke().then(() => {
  console.log(failures === 0 ? "\nALL FRONTEND CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}).catch((e) => { console.error("SMOKE ERROR:", e); process.exit(1); });
