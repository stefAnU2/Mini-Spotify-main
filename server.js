// server.js
const fs = require("fs");
const path = require("path");
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const cors = require("cors");

const SECRET = process.env.JWT_SECRET || "cambia_esto_por_una_clave_larga";

// --- DB ---
const DB_PATH = path.join(__dirname, "database.sqlite");
const db = new Database(DB_PATH);

// Migraciones simples
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS playlists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  nombre TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS playlist_songs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  playlist_id INTEGER NOT NULL,
  titulo TEXT,
  artista TEXT,
  ruta TEXT,
  duration INTEGER,
  orden INTEGER DEFAULT 0,
  FOREIGN KEY(playlist_id) REFERENCES playlists(id) ON DELETE CASCADE
);
`);

const app = express();
app.use(cors()); // en prod, restringir orígenes
app.use(bodyParser.json({ limit: "2mb" }));

// --- Helpers Auth ---
function createToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, SECRET, {
    expiresIn: "7d",
  });
}
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h) return res.status(401).json({ error: "No token" });
  const token = h.split(" ")[1];
  try {
    req.user = jwt.verify(token, SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

// --- Rutas Auth ---
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || password.length < 4) {
    return res.status(400).json({ error: "username y password (>=4)" });
  }
  const hash = await bcrypt.hash(password, 10);
  try {
    const info = db
      .prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)")
      .run(username, hash);
    const user = { id: info.lastInsertRowid, username };
    res.json({ user, token: createToken(user) });
  } catch {
    res.status(400).json({ error: "Usuario ya existe" });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};

  const row = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  // Usuario NO existe
  if (!row) {
    return res.status(400).json({ error: "Usuario inexistente" });
  }

  // Verificar contraseña
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) {
    return res.status(400).json({ error: "Contraseña incorrecta" });
  }

  // Login correcto
  const user = { id: row.id, username: row.username };
  res.json({ user, token: createToken(user) });
});


app.get("/api/me", auth, (req, res) => {
  const u = db
    .prepare("SELECT id, username, created_at FROM users WHERE id = ?")
    .get(req.user.id);
  res.json({ user: u });
});

// --- Rutas Playlists ---
app.get("/api/playlists", auth, (req, res) => {
  const data = db
    .prepare(
      "SELECT id, nombre, created_at FROM playlists WHERE user_id = ? ORDER BY created_at DESC"
    )
    .all(req.user.id);
  res.json({ playlists: data });
});

app.post("/api/playlists", auth, (req, res) => {
  const { nombre } = req.body || {};
  if (!nombre) return res.status(400).json({ error: "Nombre requerido" });
  const info = db
    .prepare("INSERT INTO playlists (user_id, nombre) VALUES (?, ?)")
    .run(req.user.id, nombre);
  const pl = db
    .prepare("SELECT id, nombre, created_at FROM playlists WHERE id = ?")
    .get(info.lastInsertRowid);
  res.json({ playlist: pl });
});

app.get("/api/playlists/:id", auth, (req, res) => {
  const id = Number(req.params.id);
  const pl = db
    .prepare(
      "SELECT id, nombre, created_at FROM playlists WHERE id = ? AND user_id = ?"
    )
    .get(id, req.user.id);
  if (!pl) return res.status(404).json({ error: "No encontrada" });
  const canciones = db
    .prepare(
      "SELECT id, titulo, artista, ruta, duration, orden FROM playlist_songs WHERE playlist_id = ? ORDER BY orden"
    )
    .all(id);
  res.json({ playlist: pl, canciones });
});

// NUEVO: Renombrar playlist
app.put("/api/playlists/:id", auth, (req, res) => {
  const id = Number(req.params.id);
  const { nombre } = req.body || {};
  if (!nombre) return res.status(400).json({ error: "Nombre requerido" });

  const own = db
    .prepare("SELECT 1 FROM playlists WHERE id = ? AND user_id = ?")
    .get(id, req.user.id);
  if (!own) return res.status(404).json({ error: "No encontrada" });

  db.prepare("UPDATE playlists SET nombre = ? WHERE id = ?").run(nombre, id);
  const pl = db
    .prepare("SELECT id, nombre, created_at FROM playlists WHERE id = ?")
    .get(id);
  res.json({ playlist: pl });
});

app.delete("/api/playlists/:id", auth, (req, res) => {
  const id = Number(req.params.id);
  db.prepare("DELETE FROM playlists WHERE id = ? AND user_id = ?").run(
    id,
    req.user.id
  );
  res.json({ ok: true });
});

app.post("/api/playlists/:id/songs", auth, (req, res) => {
  const id = Number(req.params.id);
  const { titulo, artista, ruta, duration } = req.body || {};
  const exists = db
    .prepare("SELECT 1 FROM playlists WHERE id = ? AND user_id = ?")
    .get(id, req.user.id);
  if (!exists) return res.status(404).json({ error: "Playlist no encontrada" });
  const info = db
    .prepare(
      `
    INSERT INTO playlist_songs (playlist_id, titulo, artista, ruta, duration, orden)
    VALUES (
      ?, ?, ?, ?, ?,
      COALESCE((SELECT IFNULL(MAX(orden),0)+1 FROM playlist_songs WHERE playlist_id = ?), 0)
    )
  `
    )
    .run(id, titulo, artista, ruta, duration ?? null, id);
  const song = db
    .prepare(
      "SELECT id, titulo, artista, ruta, duration, orden FROM playlist_songs WHERE id = ?"
    )
    .get(info.lastInsertRowid);
  res.json({ song });
});

app.delete("/api/playlists/:id/songs/:songId", auth, (req, res) => {
  const { id, songId } = req.params;
  db.prepare("DELETE FROM playlist_songs WHERE id = ? AND playlist_id = ?").run(
    Number(songId),
    Number(id)
  );
  res.json({ ok: true });
});

// NUEVO: Vaciar (borrar todas las canciones de la playlist)
app.delete("/api/playlists/:id/songs", auth, (req, res) => {
  const id = Number(req.params.id);
  const own = db
    .prepare("SELECT 1 FROM playlists WHERE id = ? AND user_id = ?")
    .get(id, req.user.id);
  if (!own) return res.status(404).json({ error: "Playlist no encontrada" });
  db.prepare("DELETE FROM playlist_songs WHERE playlist_id = ?").run(id);
  res.json({ ok: true });
});

// --- Servir Frontend ---
// Detecta carpeta pública automáticamente: si existe subcarpeta "Trabajo_Integrador" la usa;
// si no, usa la carpeta actual (útil cuando server.js está dentro del front).
let publicDir = fs.existsSync(path.join(__dirname, "Trabajo_Integrador"))
  ? path.join(__dirname, "Trabajo_Integrador")
  : __dirname;

// Si hay una "doble carpeta" (Trabajo_Integrador/Trabajo_Integrador), corrige:
if (
  !fs.existsSync(path.join(publicDir, "index.html")) &&
  fs.existsSync(path.join(publicDir, "Trabajo_Integrador", "index.html"))
) {
  publicDir = path.join(publicDir, "Trabajo_Integrador");
}

console.log("Public dir =>", publicDir);
console.log(
  "Tiene index.html?",
  fs.existsSync(path.join(publicDir, "index.html"))
);

app.use("/", express.static(publicDir));

// Fallback: si no hay index.html, intentá con biblioteca.html / inicio.html / home.html
app.get("/", (req, res) => {
  const candidates = [
    "index.html",
    "biblioteca.html",
    "inicio.html",
    "home.html",
  ];
  const found = candidates.find((f) => fs.existsSync(path.join(publicDir, f)));
  if (!found) {
    return res
      .status(404)
      .send(
        "No se encontró página de inicio. Busqué: " +
          candidates.join(", ") +
          " en " +
          publicDir
      );
  }
  res.sendFile(path.join(publicDir, found));
});

// Salud
app.get("/ping", (_, res) => res.send("pong"));

// --- Start ---
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
  console.log(`DB => ${DB_PATH}`);
});
