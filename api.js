// =====================
//  API CONFIG & HELPERS
// =====================
const API_BASE = "/api";

function getToken() {
  return localStorage.getItem("token");
}
function setToken(t) {
  localStorage.setItem("token", t);
}
function clearToken() {
  localStorage.removeItem("token");
}
function goLogin() {
  top.location.href = "login.html";
} // salir del frameset al login

// Fetch con auth y manejo de 401
async function apiFetch(path, opts = {}) {
  const token = getToken();
  const method = opts.method || "GET";
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      ...opts,
      method,
      headers,
      cache: "no-store",
    });
  } catch {
    throw { error: "No se pudo conectar con el servidor" };
  }

  if (res.status === 204) return {};
  let data;
  try {
    data = await res.json();
  } catch {
    data = { error: "Respuesta no válida" };
  }

  if (!res.ok) {
    if (res.status === 401) {
      clearToken();
      // Evitar bucle: si ya estoy en login.html, NO vuelvas a redirigir
      const here = (location.pathname || "").toLowerCase();
      const onLogin =
        here.endsWith("/login.html") || here.endsWith("login.html");
      if (!onLogin) goLogin();
    }
    throw data || { error: "Error" };
  }
  return data;
}

// =====================
//      ENDPOINTS
// =====================
const api = {
  // auth
  register: (u, p) =>
    apiFetch("/register", {
      method: "POST",
      body: JSON.stringify({ username: u, password: p }),
    }),
  login: (u, p) =>
    apiFetch("/login", {
      method: "POST",
      body: JSON.stringify({ username: u, password: p }),
    }),
  me: () => apiFetch("/me"),

  // playlists
  playlists: () => apiFetch("/playlists"),
  createPl: (nombre) =>
    apiFetch("/playlists", {
      method: "POST",
      body: JSON.stringify({ nombre }),
    }),
  getPl: (id) => apiFetch(`/playlists/${id}`),
  delPl: (id) => apiFetch(`/playlists/${id}`, { method: "DELETE" }),

  // NUEVOS helpers:
  renamePl: (id, nombre) =>
    apiFetch(`/playlists/${id}`, {
      method: "PUT",
      body: JSON.stringify({ nombre }),
    }),
  clearPl: (id) => apiFetch(`/playlists/${id}/songs`, { method: "DELETE" }),

  // songs
  addSong: (id, song) =>
    apiFetch(`/playlists/${id}/songs`, {
      method: "POST",
      body: JSON.stringify(song),
    }),
  delSong: (id, songId) =>
    apiFetch(`/playlists/${id}/songs/${songId}`, { method: "DELETE" }),
};

// =====================
//   AUTH EN EL FRONT
// =====================
function logout() {
  clearToken();
  goLogin();
}

async function requireAuth() {
  const t = getToken();
  if (!t) {
    goLogin();
    return false;
  }
  try {
    await api.me();
    return true;
  } catch {
    logout();
    return false;
  }
}

// Export opcional a global
window.api = api;
window.logout = logout;
window.requireAuth = requireAuth;
window.setToken = setToken;
window.getToken = getToken;
