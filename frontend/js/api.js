/* Thin API client: bearer token handling, JSON helpers, authenticated downloads. */
const Api = (() => {
  const TOKEN_KEY = "ecu_sentinel_token";
  const USER_KEY = "ecu_sentinel_user";

  const session = {
    get token() { return sessionStorage.getItem(TOKEN_KEY); },
    get user() { try { return JSON.parse(sessionStorage.getItem(USER_KEY)); } catch { return null; } },
    set(token, user) { sessionStorage.setItem(TOKEN_KEY, token); sessionStorage.setItem(USER_KEY, JSON.stringify(user)); },
    clear() { sessionStorage.removeItem(TOKEN_KEY); sessionStorage.removeItem(USER_KEY); },
  };

  class ApiError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }

  async function request(method, path, body, isForm = false) {
    const headers = {};
    if (session.token) headers.Authorization = `Bearer ${session.token}`;
    if (body && !isForm) headers["Content-Type"] = "application/json";
    const res = await fetch(path, { method, headers, body: body ? (isForm ? body : JSON.stringify(body)) : undefined });
    if (res.status === 401 && session.token) {
      session.clear();
      window.dispatchEvent(new Event("auth:expired"));
    }
    if (!res.ok) {
      let msg = `${res.status} ${res.statusText}`;
      try {
        const data = await res.json();
        if (data.detail) msg = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
      } catch { /* non-JSON error */ }
      throw new ApiError(res.status, msg);
    }
    const type = res.headers.get("content-type") || "";
    return type.includes("application/json") ? res.json() : res.text();
  }

  async function download(path, fallbackName) {
    const res = await fetch(path, { headers: { Authorization: `Bearer ${session.token}` } });
    if (!res.ok) throw new ApiError(res.status, "Download failed");
    const blob = await res.blob();
    const cd = res.headers.get("content-disposition") || "";
    const name = (cd.match(/filename="([^"]+)"/) || [])[1] || fallbackName;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return { name };
  }

  return {
    session, ApiError, download,
    get: (p) => request("GET", p),
    post: (p, b) => request("POST", p, b || {}),
    upload: (p, form) => request("POST", p, form, true),
  };
})();
