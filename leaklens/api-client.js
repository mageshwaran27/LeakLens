/* LeakLens API client — fetch wrapper for the local backend.
   Base defaults to http://127.0.0.1:8000. Bearer token is persisted in
   localStorage and sent on every request. 401s trigger onUnauthorized. */
(function () {
  "use strict";
  var BASE = (window.LEAKLENS_API || "http://127.0.0.1:8000").replace(/\/$/, "");
  var KEY = "leaklens_token";
  var _token = "";
  try { _token = localStorage.getItem(KEY) || ""; } catch (e) { _token = ""; }
  var _on401 = null;

  function setToken(t) {
    _token = t || "";
    try {
      if (t) localStorage.setItem(KEY, t);
      else localStorage.removeItem(KEY);
    } catch (e) { /* private mode etc. — token just won't persist */ }
  }

  async function req(path, opts, timeoutMs) {
    opts = opts || {};
    var headers = {};
    for (var k in (opts.headers || {})) headers[k] = opts.headers[k];
    if (_token) headers["Authorization"] = "Bearer " + _token;
    var isForm = (typeof FormData !== "undefined") && (opts.body instanceof FormData);
    if (opts.body !== undefined && !isForm && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, timeoutMs || 30000);
    var r;
    try {
      var init = { headers: headers, signal: ctrl.signal, method: opts.method || "GET" };
      if (opts.body !== undefined) init.body = isForm ? opts.body : JSON.stringify(opts.body);
      r = await fetch(BASE + path, init);
    } catch (e) {
      clearTimeout(timer);
      throw new Error(e && e.name === "AbortError"
        ? "Request timed out: " + path
        : "Cannot reach backend at " + BASE + " — is it running?");
    }
    clearTimeout(timer);
    if (r.status === 401) {
      setToken("");
      if (_on401) { try { _on401(); } catch (e) { /* ignore */ } }
      var why = "Authentication required — please log in";
      try {
        var j = await r.json();
        if (j && j.detail) why = j.detail;
      } catch (e) { /* ignore */ }
      throw new Error(why);
    }
    var data = null;
    try {
      var ct = r.headers.get("content-type") || "";
      data = ct.indexOf("json") >= 0 ? await r.json() : await r.text();
    } catch (e) { data = null; }
    if (!r.ok) {
      var msg = (data && data.detail) ? data.detail : ("API " + r.status + " " + path);
      throw new Error(typeof msg === "string" ? msg : JSON.stringify(msg));
    }
    return data;
  }

  async function download(path) {
    var headers = {};
    if (_token) headers["Authorization"] = "Bearer " + _token;
    var r = await fetch(BASE + path, { headers: headers });
    if (r.status === 401) {
      setToken("");
      if (_on401) { try { _on401(); } catch (e) { /* ignore */ } }
      throw new Error("Authentication required — please log in");
    }
    if (!r.ok) throw new Error("API " + r.status + " " + path);
    return r;
  }

  function post(path, body) { return req(path, { method: "POST", body: body }); }
  function patch(path, body) { return req(path, { method: "PATCH", body: body }); }
  function del(path) { return req(path, { method: "DELETE" }); }

  window.LeakLensAPI = {
    base: BASE,
    setToken: setToken,
    hasToken: function () { return !!_token; },
    onUnauthorized: function (fn) { _on401 = fn; },

    authStatus: function () { return req("/api/auth/status"); },
    setup: function (b) { return post("/api/auth/setup", b); },
    login: function (b) { return post("/api/auth/login", b); },
    logout: function () { return post("/api/auth/logout", {}); },
    me: function () { return req("/api/auth/me"); },

    health: function () { return req("/health"); },
    dashboard: function () { return req("/api/dashboard"); },

    projects: function () { return req("/api/projects"); },
    project: function (id) { return req("/api/projects/" + encodeURIComponent(id)); },
    createProject: function (b) { return post("/api/projects", b); },
    deleteProject: function (id) { return del("/api/projects/" + encodeURIComponent(id)); },

    uploadZip: function (file) {
      var fd = new FormData();
      fd.append("file", file);
      return req("/api/uploads", { method: "POST", body: fd }, 300000);
    },
    deleteUpload: function (id) { return del("/api/uploads/" + encodeURIComponent(id)); },

    startScan: function (b) { return post("/api/scans", b); },
    scans: function (projectId) {
      return req("/api/scans" + (projectId ? "?project_id=" + encodeURIComponent(projectId) : ""));
    },
    scan: function (id) { return req("/api/scans/" + encodeURIComponent(id)); },
    scanProgress: function (id) { return req("/api/scans/" + encodeURIComponent(id) + "/progress"); },
    cancelScan: function (id) { return post("/api/scans/" + encodeURIComponent(id) + "/cancel", {}); },

    findings: function (q) { return req("/api/findings" + (q || "")); },
    finding: function (id) { return req("/api/findings/" + encodeURIComponent(id)); },
    updateFinding: function (id, status) { return patch("/api/findings/" + encodeURIComponent(id), { status: status }); },
    bulkUpdate: function (ids, status) { return post("/api/findings/bulk-update", { ids: ids, status: status }); },

    reports: function (projectId) {
      return req("/api/reports" + (projectId ? "?project_id=" + encodeURIComponent(projectId) : ""));
    },
    createReport: function (b) { return post("/api/reports", b); },
    deleteReport: function (id) { return del("/api/reports/" + encodeURIComponent(id)); },
    downloadReport: function (id) { return download("/api/reports/" + encodeURIComponent(id) + "/download"); },

    runBenchmark: function (b) { return post("/api/benchmarks/run", b || {}); },
    benchmarkJob: function (id) { return req("/api/benchmarks/jobs/" + encodeURIComponent(id)); },
    benchmarks: function () { return req("/api/benchmarks"); },
    benchmark: function (id) { return req("/api/benchmarks/" + encodeURIComponent(id)); },

    models: function () { return req("/api/models"); },
    activeModel: function () { return req("/api/models/active"); },
    modelMetrics: function () { return req("/api/models/metrics"); },
    datasets: function () { return req("/api/datasets"); },
    datasetStats: function () { return req("/api/datasets/statistics"); },

    activity: function () { return req("/api/activity"); },
    settings: function () { return req("/api/settings"); },
    saveSettings: function (b) { return post("/api/settings", b); }
  };
})();
