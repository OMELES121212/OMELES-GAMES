const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const { Server } = require("socket.io");
const Database = require("better-sqlite3");
const db = require("./database");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] },
    transports: ["polling", "websocket"]
});

const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || "OMELES-ADMIN-2026";

/* ============ UPLOADS ============ */
const UPLOADS_DIR = process.env.DB_PATH
    ? path.join(path.dirname(process.env.DB_PATH), "uploads")
    : path.join(__dirname, "public", "uploads");
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
console.log(`📂 Uploads en: ${UPLOADS_DIR}`);

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOADS_DIR),
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        const name = Date.now() + "-" + crypto.randomBytes(4).toString("hex") + ext;
        cb(null, name);
    }
});
const upload = multer({
    storage,
    limits: { fileSize: 1024 * 1024 * 1024 } // 1 GB
});

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(UPLOADS_DIR));

/* ============ UTILS ============ */
function hashPassword(pw) {
    const salt = crypto.randomBytes(16).toString("hex");
    const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
    return `${salt}:${hash}`;
}
function verifyPassword(pw, stored) {
    try {
        const [salt, hash] = stored.split(":");
        const check = crypto.scryptSync(pw, salt, 64).toString("hex");
        return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(check, "hex"));
    } catch { return false; }
}

const intentos = new Map();
function rateLimit(req, res, next) {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const ahora = Date.now();
    const d = intentos.get(ip) || { count: 0, reset: ahora + 60000 };
    if (ahora > d.reset) { d.count = 0; d.reset = ahora + 60000; }
    d.count++;
    intentos.set(ip, d);
    if (d.count > 60) return res.status(429).json({ success: false, message: "Demasiados intentos." });
    next();
}

/* ============ ADMIN MIDDLEWARE ============ */
function checkAdmin(req, res, next) {
    const key = req.headers["x-admin-key"];
    if (key === ADMIN_KEY) {
        req.adminIsRoot = true;
        req.adminPermissions = ["*"];
        return next();
    }
    const row = db.prepare("SELECT * FROM keys WHERE key = ? AND type LIKE 'ADMIN%'").get(key);
    if (!row) return res.status(401).json({ success: false, message: "Admin Key incorrecta" });
    if (row.expires_at && new Date(row.expires_at) <= new Date()) {
        db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(row.id);
        return res.status(401).json({ success: false, message: "Admin Key expirada" });
    }
    if (!row.active) return res.status(401).json({ success: false, message: "Admin Key revocada" });
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?";
    db.prepare(`UPDATE keys SET last_ip = ?, last_used_at = ?, use_count = use_count + 1 WHERE id = ?`)
      .run(ip, new Date().toISOString(), row.id);
    let perms = [];
    try { perms = row.permissions ? JSON.parse(row.permissions) : []; } catch {}
    req.adminIsRoot = false;
    req.adminPermissions = perms;
    req.adminRow = row;
    next();
}

/* ============ HELPER JUEGOS ============ */
function resolverJuegosPermitidos(row) {
    const mode = row.game_mode || "all";
    const allActive = db.prepare("SELECT * FROM games WHERE active = 1 ORDER BY id DESC").all();
    if (mode === "none") return [];
    if (mode === "all") return allActive;
    let ids = [];
    if (row.allowed_games) { try { ids = JSON.parse(row.allowed_games); } catch { ids = []; } }
    if (mode === "whitelist") {
        if (!Array.isArray(ids) || ids.length === 0) return [];
        const ph = ids.map(() => "?").join(",");
        return db.prepare(`SELECT * FROM games WHERE active = 1 AND id IN (${ph}) ORDER BY id DESC`).all(...ids);
    }
    if (mode === "blacklist") {
        if (!Array.isArray(ids) || ids.length === 0) return allActive;
        const ph = ids.map(() => "?").join(",");
        return db.prepare(`SELECT * FROM games WHERE active = 1 AND id NOT IN (${ph}) ORDER BY id DESC`).all(...ids);
    }
    return allActive;
}

/* ============ SOCKET ============ */
io.use((socket, next) => {
    const key = socket.handshake.auth.key;
    if (key) socket.data.key = key;
    next();
});
io.on("connection", (socket) => {
    if (socket.data.key) socket.join(`key:${socket.data.key}`);
    console.log(`🔌 Cliente: ${socket.id}`);
});

/* ============================================================
   SUBIR ARCHIVOS
============================================================ */
app.post("/api/admin/upload", checkAdmin, upload.single("file"), (req, res) => {
    if (!req.file) return res.status(400).json({ success: false, message: "No se subió archivo" });
    res.json({
        success: true,
        url: "/uploads/" + req.file.filename,
        filename: req.file.filename,
        originalname: req.file.originalname,
        size: req.file.size
    });
});

/* ============================================================
   REGISTRO / LOGIN
============================================================ */
app.post("/api/register", rateLimit, (req, res) => {
    const { key, username, password } = req.body;
    if (!key || !username || !password)
        return res.status(400).json({ success: false, message: "Rellena todos los campos" });
    if (username.length < 3 || username.length > 20)
        return res.status(400).json({ success: false, message: "Usuario: entre 3 y 20 caracteres" });
    if (!/^[a-zA-Z0-9_.-]+$/.test(username))
        return res.status(400).json({ success: false, message: "Usuario inválido" });
    if (password.length < 4)
        return res.status(400).json({ success: false, message: "Contraseña: mínimo 4" });

    const keyRow = db.prepare("SELECT * FROM keys WHERE key = ?").get(key.trim());
    if (!keyRow) return res.status(401).json({ success: false, message: "Key no válida" });
    if (!keyRow.active) return res.status(401).json({ success: false, message: "Key revocada o ya usada" });
    if (keyRow.expires_at && new Date(keyRow.expires_at) <= new Date()) {
        db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(keyRow.id);
        return res.status(401).json({ success: false, message: "Key expirada" });
    }
    const yaAsignada = db.prepare("SELECT id, username FROM users WHERE key_id = ?").get(keyRow.id);
    if (yaAsignada) return res.status(409).json({ success: false, message: `Key ya registrada por "${yaAsignada.username}"` });
    const yaExiste = db.prepare("SELECT id FROM users WHERE username = ?").get(username.trim());
    if (yaExiste) return res.status(409).json({ success: false, message: "Nombre en uso" });

    try {
        const hash = hashPassword(password);
        const now = new Date().toISOString();
        db.prepare(`INSERT INTO users (username, password_hash, key_id, created_at, last_login, plain_password)
            VALUES (?, ?, ?, ?, ?, ?)`)
          .run(username.trim(), hash, keyRow.id, now, now, password);
        const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?";
        db.prepare(`UPDATE keys SET last_ip = ?, last_used_at = ?, use_count = use_count + 1 WHERE id = ?`)
          .run(ip, now, keyRow.id);
        const juegosPermitidos = resolverJuegosPermitidos(keyRow);
        const allowed = keyRow.game_mode === "all" ? null : juegosPermitidos.map(g => g.id);
        res.json({ success: true, user: { username: username.trim() }, key: keyRow.key, type: keyRow.type, allowed });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Error al registrar" });
    }
});

app.post("/api/login-user", rateLimit, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "Faltan datos" });
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
    if (!user) return res.status(401).json({ success: false, message: "Usuario o contraseña incorrectos" });
    if (!verifyPassword(password, user.password_hash))
        return res.status(401).json({ success: false, message: "Usuario o contraseña incorrectos" });
    const key = db.prepare("SELECT * FROM keys WHERE id = ?").get(user.key_id);
    if (!key) return res.status(401).json({ success: false, message: "Key no encontrada" });
    if (!key.active) return res.status(401).json({ success: false, message: "Tu key ha sido revocada" });
    if (key.expires_at && new Date(key.expires_at) <= new Date()) {
        db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(key.id);
        return res.status(401).json({ success: false, message: "Tu key ha expirado" });
    }
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?";
    const now = new Date().toISOString();
    db.prepare("UPDATE users SET last_login = ? WHERE id = ?").run(now, user.id);
    db.prepare(`UPDATE keys SET last_ip = ?, last_used_at = ?, use_count = use_count + 1 WHERE id = ?`)
      .run(ip, now, key.id);
    const juegosPermitidos = resolverJuegosPermitidos(key);
    const allowed = key.game_mode === "all" ? null : juegosPermitidos.map(g => g.id);
    res.json({ success: true, user: { username: user.username }, key: key.key, type: key.type, allowed });
});

app.post("/api/login", rateLimit, (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ success: false, message: "Falta key" });
    const row = db.prepare("SELECT * FROM keys WHERE key = ?").get(key);
    if (!row) return res.status(401).json({ success: false, message: "Key no válida" });
    if (!row.active) return res.status(401).json({ success: false, message: "Key revocada o ya usada" });
    if (row.expires_at && new Date(row.expires_at) <= new Date()) {
        db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(row.id);
        return res.status(401).json({ success: false, message: "Key expirada" });
    }
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?";
    const uses = (row.use_count || 0) + 1;
    const esUnSoloUso = row.type === "ONE_USE" || row.type === "ADMIN_ONE_USE";
    const active = esUnSoloUso ? 0 : 1;
    db.prepare(`UPDATE keys SET last_ip = ?, last_used_at = ?, use_count = ?, active = ? WHERE id = ?`)
      .run(ip, new Date().toISOString(), uses, active, row.id);
    const juegosPermitidos = resolverJuegosPermitidos(row);
    const allowed = row.game_mode === "all" ? null : juegosPermitidos.map(g => g.id);
    res.json({ success: true, type: row.type, allowed, game_mode: row.game_mode });
});

/* ============ ADMIN INFO ============ */
app.get("/api/admin/me", checkAdmin, (req, res) => {
    res.json({
        success: true,
        isRoot: req.adminIsRoot,
        permissions: req.adminPermissions,
        nickname: req.adminIsRoot ? "Root Admin" : (req.adminRow?.nickname || "Admin")
    });
});

/* ============ PRODUCTOS DEL USUARIO ============ */
app.get("/api/games", (req, res) => {
    const key = req.headers["x-user-key"];
    if (!key) return res.status(401).json({ success: false, message: "Falta key" });
    const row = db.prepare("SELECT * FROM keys WHERE key = ?").get(key);
    if (!row) return res.status(401).json({ success: false, message: "Key no válida" });
    const games = resolverJuegosPermitidos(row);
    const cats = db.prepare("SELECT * FROM categories ORDER BY position ASC, id ASC").all();
    const gc = db.prepare("SELECT * FROM game_categories").all();
    const map = {};
    gc.forEach(x => { if (!map[x.game_id]) map[x.game_id] = []; map[x.game_id].push(x.category_id); });
    games.forEach(g => { g.categories = map[g.id] || []; });
    res.json({ success: true, games, categories: cats });
});

/* ============================================================
   KEYS
============================================================ */
app.get("/api/admin/keys", checkAdmin, (req, res) => {
    const keys = db.prepare("SELECT * FROM keys WHERE key != ? ORDER BY id DESC").all(ADMIN_KEY);
    res.json({ success: true, keys });
});

app.post("/api/keys", checkAdmin, (req, res) => {
    const { type, gameId, gameIds, permissions, massive, count, gameMode } = req.body;
    const validos = ["24H","7D","30D","LIFETIME","ONE_USE","ADMIN","ADMIN_24H","ADMIN_7D","ADMIN_30D","ADMIN_ONE_USE","ADMIN_LIFETIME"];
    if (!validos.includes(type)) return res.status(400).json({ success: false, message: "Tipo inválido" });

    let permsValue = null;
    if (type.startsWith("ADMIN")) {
        const canGrant = req.adminIsRoot || req.adminPermissions.includes("*") || req.adminPermissions.includes("manage_permissions");
        if (!canGrant) return res.status(403).json({ success: false, message: "Sin permiso" });
        permsValue = Array.isArray(permissions) ? JSON.stringify(permissions) : JSON.stringify(["*"]);
    }

    let mode = String(gameMode || "all").toLowerCase();
    if (!["all","none","whitelist","blacklist"].includes(mode)) mode = "all";

    let ids = [];
    if (Array.isArray(gameIds) && gameIds.length > 0) ids = gameIds.map(Number).filter(n => Number.isFinite(n) && n > 0);
    else if (gameId !== undefined && gameId !== null && gameId !== "") {
        const gid = Number(gameId);
        if (Number.isFinite(gid) && gid > 0) ids = [gid];
    }

    if (ids.length > 0) {
        const ph = ids.map(() => "?").join(",");
        const found = db.prepare(`SELECT id FROM games WHERE active = 1 AND id IN (${ph})`).all(...ids);
        if (found.length !== ids.length) return res.status(404).json({ success: false, message: "Algún producto no existe" });
    }

    let allowed_games = null;
    let gameIdPrefix = "";
    if (mode === "whitelist" || mode === "blacklist") {
        allowed_games = JSON.stringify(ids);
        if (mode === "whitelist" && ids.length === 1) gameIdPrefix = `${ids[0]}-`;
    }

    const numCount = massive ? Math.min(Math.max(Number(count) || 1, 1), 500) : 1;
    const isMassiveFlag = massive ? 1 : 0;
    const rand = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    const now = new Date();
    let expires = null;
    if (type === "24H" || type === "ADMIN_24H") expires = new Date(now.getTime() + 24*3600*1000).toISOString();
    if (type === "7D" || type === "ADMIN_7D") expires = new Date(now.getTime() + 7*24*3600*1000).toISOString();
    if (type === "30D" || type === "ADMIN_30D") expires = new Date(now.getTime() + 30*24*3600*1000).toISOString();

    const generatedKeys = [];
    try {
        const stmt = db.prepare(`INSERT INTO keys (key, type, created_at, expires_at, active, allowed_games, permissions, massive, game_mode) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)`);
        const checkStmt = db.prepare("SELECT id FROM keys WHERE key = ?");
        const doInsert = db.transaction(() => {
            for (let i = 0; i < numCount; i++) {
                let keyStr, attempts = 0;
                do { keyStr = `OMELES-${gameIdPrefix}${rand()}-${rand()}`; attempts++; }
                while (checkStmt.get(keyStr) && attempts < 20);
                stmt.run(keyStr, type, now.toISOString(), expires, allowed_games, permsValue, isMassiveFlag, mode);
                generatedKeys.push(keyStr);
            }
        });
        doInsert();
    } catch (e) {
        console.error(e);
        return res.status(500).json({ success: false, message: "Error al generar" });
    }

    if (massive) io.emit("keys-massive-created", { count: generatedKeys.length });
    res.json({ success: true, key: generatedKeys[0], keys: generatedKeys, count: generatedKeys.length, massive: !!massive, gameMode: mode });
});

app.post("/api/admin/update-key-permissions", checkAdmin, (req, res) => {
    const { id, permissions } = req.body;
    const canGrant = req.adminIsRoot || req.adminPermissions.includes("*") || req.adminPermissions.includes("manage_permissions");
    if (!canGrant) return res.status(403).json({ success: false, message: "Sin permiso" });
    const row = db.prepare("SELECT * FROM keys WHERE id = ?").get(id);
    if (!row) return res.status(404).json({ success: false, message: "No encontrada" });
    if (row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes tocar el Root" });
    if (!row.type.startsWith("ADMIN")) return res.status(400).json({ success: false, message: "No es admin" });
    const value = Array.isArray(permissions) ? JSON.stringify(permissions) : JSON.stringify(["*"]);
    db.prepare("UPDATE keys SET permissions = ? WHERE id = ?").run(value, id);
    res.json({ success: true });
});

app.post("/api/admin/update-key-nickname", checkAdmin, (req, res) => {
    const { id, nickname } = req.body;
    const row = db.prepare("SELECT key FROM keys WHERE id = ?").get(id);
    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes tocar el Root" });
    db.prepare("UPDATE keys SET nickname = ? WHERE id = ?").run(nickname || "", id);
    res.json({ success: true });
});

app.get("/api/admin/key-games/:id", checkAdmin, (req, res) => {
    const row = db.prepare("SELECT allowed_games, game_mode FROM keys WHERE id = ?").get(req.params.id);
    if (!row) return res.status(404).json({ success: false, message: "No encontrada" });
    const allGames = db.prepare("SELECT id, name, created_at FROM games WHERE active = 1 ORDER BY name").all();
    let allowed = null;
    if (row.allowed_games) { try { allowed = JSON.parse(row.allowed_games); } catch { allowed = []; } }
    res.json({ success: true, allowed, allGames, gameMode: row.game_mode || "all" });
});

app.post("/api/admin/update-key-games", checkAdmin, (req, res) => {
    const { id, allowed, gameMode } = req.body;
    if (!id) return res.status(400).json({ success: false, message: "Falta id" });
    const row = db.prepare("SELECT * FROM keys WHERE id = ?").get(id);
    if (!row) return res.status(404).json({ success: false, message: "No encontrada" });
    let mode = gameMode ? String(gameMode).toLowerCase() : (row.game_mode || "all");
    if (!["all","none","whitelist","blacklist"].includes(mode)) mode = "all";
    let value = null;
    if (Array.isArray(allowed)) {
        if (mode === "whitelist" || mode === "blacklist") value = JSON.stringify(allowed.map(Number));
    }
    db.prepare("UPDATE keys SET allowed_games = ?, game_mode = ? WHERE id = ?").run(value, mode, id);
    const row2 = db.prepare("SELECT key FROM keys WHERE id = ?").get(id);
    if (row2) io.to(`key:${row2.key}`).emit("key-updated", { key: row2.key });
    res.json({ success: true });
});

app.post("/api/admin/reactivate-key", checkAdmin, (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ success: false, message: "Falta id" });
    const row = db.prepare("SELECT * FROM keys WHERE id = ?").get(id);
    if (!row) return res.status(404).json({ success: false, message: "No encontrada" });
    if (row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes tocar el Root" });
    db.prepare("UPDATE keys SET active = 1 WHERE id = ?").run(id);
    io.to(`key:${row.key}`).emit("key-updated", { key: row.key });
    res.json({ success: true });
});

app.post("/api/admin/reactivate-massive-keys", checkAdmin, (req, res) => {
    const canGrant = req.adminIsRoot || req.adminPermissions.includes("*") || req.adminPermissions.includes("manage_permissions");
    if (!canGrant) return res.status(403).json({ success: false, message: "Sin permiso" });
    const info = db.prepare("SELECT id FROM keys WHERE massive = 1 AND active = 0").all();
    if (info.length === 0) return res.json({ success: true, reactivated: 0 });
    const ids = info.map(k => k.id);
    const ph = ids.map(() => "?").join(",");
    db.prepare(`UPDATE keys SET active = 1 WHERE id IN (${ph})`).run(...ids);
    io.emit("keys-massive-created", { count: ids.length });
    res.json({ success: true, reactivated: ids.length });
});

app.post("/api/admin/revoke-key", checkAdmin, (req, res) => {
    const row = db.prepare("SELECT key, type FROM keys WHERE id = ?").get(req.body.id);
    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes revocar el Root" });
    db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(req.body.id);
    if (row) io.emit("key-revoked", { key: row.key, type: row.type });
    res.json({ success: true });
});

app.post("/api/admin/delete-key", checkAdmin, (req, res) => {
    const row = db.prepare("SELECT key, type FROM keys WHERE id = ?").get(req.body.id);
    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes borrar el Root" });
    db.prepare("DELETE FROM users WHERE key_id = ?").run(req.body.id);
    db.prepare("DELETE FROM keys WHERE id = ?").run(req.body.id);
    if (row) io.emit("key-revoked", { key: row.key, type: row.type });
    res.json({ success: true });
});

app.post("/api/admin/delete-massive-keys", checkAdmin, (req, res) => {
    const canGrant = req.adminIsRoot || req.adminPermissions.includes("*") || req.adminPermissions.includes("manage_permissions");
    if (!canGrant) return res.status(403).json({ success: false, message: "Sin permiso" });
    const info = db.prepare("SELECT id FROM keys WHERE massive = 1").all();
    if (info.length === 0) return res.json({ success: true, deleted: 0 });
    const ids = info.map(k => k.id);
    const ph = ids.map(() => "?").join(",");
    db.prepare(`DELETE FROM users WHERE key_id IN (${ph})`).run(...ids);
    db.prepare(`DELETE FROM keys WHERE id IN (${ph})`).run(...ids);
    io.emit("keys-massive-deleted", { count: ids.length });
    res.json({ success: true, deleted: ids.length });
});

/* ============ USUARIOS (admin) ============ */
app.get("/api/admin/users", checkAdmin, (req, res) => {
    const users = db.prepare(`
        SELECT u.id, u.username, u.created_at, u.last_login, u.key_id, u.plain_password, u.pinned,
               k.key as key_value, k.type as key_type, k.nickname as key_nickname,
               k.active as key_active, k.expires_at as key_expires
        FROM users u
        LEFT JOIN keys k ON u.key_id = k.id
        ORDER BY u.pinned DESC, u.id DESC
    `).all();
    res.json({ success: true, users });
});

app.post("/api/admin/toggle-user-pin", checkAdmin, (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ success: false, message: "Falta id" });
    const row = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
    if (!row) return res.status(404).json({ success: false, message: "No encontrado" });
    const nuevo = row.pinned ? 0 : 1;
    db.prepare("UPDATE users SET pinned = ? WHERE id = ?").run(nuevo, id);
    res.json({ success: true, pinned: nuevo });
});

app.post("/api/admin/delete-user", checkAdmin, (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ success: false, message: "Falta id" });
    db.prepare("DELETE FROM users WHERE id = ?").run(id);
    res.json({ success: true });
});

app.post("/api/admin/reset-user-password", checkAdmin, (req, res) => {
    const { id, newPassword } = req.body;
    if (!id || !newPassword || newPassword.length < 4)
        return res.status(400).json({ success: false, message: "Mínimo 4 caracteres" });
    const hash = hashPassword(newPassword);
    db.prepare("UPDATE users SET password_hash = ?, plain_password = ? WHERE id = ?").run(hash, newPassword, id);
    res.json({ success: true });
});

/* ============================================================
   PRODUCTOS (admin)
============================================================ */
app.get("/api/admin/games", checkAdmin, (req, res) => {
    const games = db.prepare("SELECT * FROM games ORDER BY id DESC").all();
    const gc = db.prepare("SELECT * FROM game_categories").all();
    const map = {};
    gc.forEach(x => { if (!map[x.game_id]) map[x.game_id] = []; map[x.game_id].push(x.category_id); });
    games.forEach(g => { g.categories = map[g.id] || []; });
    res.json({ success: true, games });
});

app.post("/api/games", checkAdmin, (req, res) => {
    const { name, download, repair, password, image, type, description, content_url, content_file } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Falta nombre" });
    const t = type || "game";
    db.prepare(`INSERT INTO games (name, download, repair, password, image, active, created_at, type, description, content_url, content_file)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`)
      .run(name, download || "", repair || "", password || "", image || "", new Date().toISOString(),
           t, description || "", content_url || "", content_file || "");
    io.emit("games-updated", { action: "create", name });
    res.json({ success: true });
});

app.post("/api/admin/update-game", checkAdmin, (req, res) => {
    const { id, name, download, repair, password, image, type, description, content_url, content_file } = req.body;
    db.prepare(`UPDATE games SET name = ?, download = ?, repair = ?, password = ?, image = ?, type = ?, description = ?, content_url = ?, content_file = ? WHERE id = ?`)
      .run(name, download || "", repair || "", password || "", image || "",
           type || "game", description || "", content_url || "", content_file || "", id);
    io.emit("games-updated", { action: "update", name });
    res.json({ success: true });
});

app.post("/api/admin/delete-game", checkAdmin, (req, res) => {
    db.prepare("DELETE FROM games WHERE id = ?").run(req.body.id);
    io.emit("games-updated", { action: "delete" });
    res.json({ success: true });
});

/* ============================================================
   CATEGORÍAS
============================================================ */
app.get("/api/admin/categories", checkAdmin, (req, res) => {
    const cats = db.prepare("SELECT * FROM categories ORDER BY position ASC, id ASC").all();
    const gc = db.prepare("SELECT * FROM game_categories").all();
    const map = {};
    gc.forEach(x => { if (!map[x.category_id]) map[x.category_id] = []; map[x.category_id].push(x.game_id); });
    cats.forEach(c => { c.games = map[c.id] || []; });
    res.json({ success: true, categories: cats });
});

app.post("/api/admin/categories/create", checkAdmin, (req, res) => {
    const { name, icon, color } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Falta nombre" });
    const maxPos = db.prepare("SELECT COALESCE(MAX(position), -1) as m FROM categories").get().m;
    const info = db.prepare(`INSERT INTO categories (name, icon, color, position, created_at) VALUES (?, ?, ?, ?, ?)`)
      .run(name.trim(), icon || "📁", color || "#8b5cff", maxPos + 1, new Date().toISOString());
    io.emit("categories-updated", { action: "create" });
    res.json({ success: true, id: info.lastInsertRowid });
});

app.post("/api/admin/categories/update", checkAdmin, (req, res) => {
    const { id, name, icon, color } = req.body;
    if (!id || !name) return res.status(400).json({ success: false, message: "Faltan datos" });
    db.prepare("UPDATE categories SET name = ?, icon = ?, color = ? WHERE id = ?")
      .run(name.trim(), icon || "📁", color || "#8b5cff", id);
    io.emit("categories-updated", { action: "update" });
    res.json({ success: true });
});

app.post("/api/admin/categories/delete", checkAdmin, (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ success: false, message: "Falta id" });
    db.prepare("DELETE FROM categories WHERE id = ?").run(id);
    io.emit("categories-updated", { action: "delete" });
    res.json({ success: true });
});

// Checklist: actualizar TODOS los productos de una categoría a la vez
app.post("/api/admin/categories/set-games", checkAdmin, (req, res) => {
    const { categoryId, gameIds } = req.body;
    if (!categoryId) return res.status(400).json({ success: false, message: "Falta categoryId" });
    if (!Array.isArray(gameIds)) return res.status(400).json({ success: false, message: "gameIds inválido" });

    const tx = db.transaction(() => {
        db.prepare("DELETE FROM game_categories WHERE category_id = ?").run(categoryId);
        const stmt = db.prepare("INSERT OR IGNORE INTO game_categories (game_id, category_id, position) VALUES (?, ?, 0)");
        gameIds.map(Number).forEach(gid => stmt.run(gid, categoryId));
    });
    tx();

    io.emit("categories-updated", { action: "set-games" });
    res.json({ success: true, count: gameIds.length });
});

app.get("/api/admin/categories/:id/games", checkAdmin, (req, res) => {
    const catId = req.params.id;
    const games = db.prepare(`
        SELECT g.* FROM games g
        INNER JOIN game_categories gc ON gc.game_id = g.id
        WHERE gc.category_id = ?
        ORDER BY gc.position ASC, g.id DESC
    `).all(catId);
    res.json({ success: true, games });
});

/* ============================================================
   TICKETS
============================================================ */
app.post("/api/tickets/create", rateLimit, (req, res) => {
    const { userKey, username, subject, message, priority } = req.body;
    if (!username || !subject || !message)
        return res.status(400).json({ success: false, message: "Rellena todos los campos" });
    if (subject.length > 100) return res.status(400).json({ success: false, message: "Asunto muy largo" });
    if (message.length > 2000) return res.status(400).json({ success: false, message: "Mensaje muy largo" });

    let userId = null;
    if (userKey) {
        const u = db.prepare("SELECT id FROM users WHERE key_id = (SELECT id FROM keys WHERE key = ?)").get(userKey);
        if (u) userId = u.id;
    }

    const now = new Date().toISOString();
    const info = db.prepare(`INSERT INTO tickets (user_id, username, user_key, subject, status, priority, created_at, updated_at, last_reply_by)
        VALUES (?, ?, ?, ?, 'open', ?, ?, ?, 'user')`)
      .run(userId, username.trim(), userKey || null, subject.trim(), priority || "normal", now, now);

    db.prepare(`INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message, created_at)
        VALUES (?, 'user', ?, ?, ?)`)
      .run(info.lastInsertRowid, username.trim(), message.trim(), now);

    io.emit("ticket-created", { id: info.lastInsertRowid, username: username.trim(), subject: subject.trim() });
    res.json({ success: true, id: info.lastInsertRowid });
});

app.get("/api/tickets/my", (req, res) => {
    const userKey = req.headers["x-user-key"];
    if (!userKey) return res.status(401).json({ success: false, message: "Falta key" });
    const tickets = db.prepare(`SELECT * FROM tickets WHERE user_key = ? ORDER BY updated_at DESC`).all(userKey);
    res.json({ success: true, tickets });
});

app.get("/api/tickets/:id", (req, res) => {
    const id = req.params.id;
    const adminKey = req.headers["x-admin-key"];
    const userKey = req.headers["x-user-key"];
    const t = db.prepare("SELECT * FROM tickets WHERE id = ?").get(id);
    if (!t) return res.status(404).json({ success: false, message: "Ticket no encontrado" });
    const isAdmin = adminKey && (adminKey === ADMIN_KEY || db.prepare("SELECT id FROM keys WHERE key = ? AND type LIKE 'ADMIN%'").get(adminKey));
    const isOwner = userKey && t.user_key === userKey;
    if (!isAdmin && !isOwner) return res.status(403).json({ success: false, message: "Sin acceso" });
    const messages = db.prepare("SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY id ASC").all(id);
    res.json({ success: true, ticket: t, messages });
});

app.post("/api/tickets/:id/reply", rateLimit, (req, res) => {
    const id = req.params.id;
    const { userKey, message } = req.body;
    if (!userKey || !message) return res.status(400).json({ success: false, message: "Faltan datos" });
    const t = db.prepare("SELECT * FROM tickets WHERE id = ?").get(id);
    if (!t) return res.status(404).json({ success: false, message: "No encontrado" });
    if (t.user_key !== userKey) return res.status(403).json({ success: false, message: "Sin acceso" });
    if (t.status === "closed") return res.status(400).json({ success: false, message: "Ticket cerrado" });
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message, created_at)
        VALUES (?, 'user', ?, ?, ?)`)
      .run(id, t.username, message.trim(), now);
    db.prepare("UPDATE tickets SET updated_at = ?, status = 'open', last_reply_by = 'user' WHERE id = ?").run(now, id);
    io.emit("ticket-reply", { id, from: "user" });
    res.json({ success: true });
});

app.get("/api/admin/tickets", checkAdmin, (req, res) => {
    const filtro = req.query.filter || "all";
    let tickets;
    if (filtro === "all") tickets = db.prepare("SELECT * FROM tickets ORDER BY updated_at DESC").all();
    else tickets = db.prepare("SELECT * FROM tickets WHERE status = ? ORDER BY updated_at DESC").all(filtro);
    const counts = {};
    db.prepare("SELECT ticket_id, COUNT(*) as c FROM ticket_messages GROUP BY ticket_id").all().forEach(x => counts[x.ticket_id] = x.c);
    tickets.forEach(t => t.message_count = counts[t.id] || 0);
    const stats = {
        total: db.prepare("SELECT COUNT(*) as c FROM tickets").get().c,
        open: db.prepare("SELECT COUNT(*) as c FROM tickets WHERE status = 'open'").get().c,
        pending: db.prepare("SELECT COUNT(*) as c FROM tickets WHERE status = 'pending'").get().c,
        closed: db.prepare("SELECT COUNT(*) as c FROM tickets WHERE status = 'closed'").get().c
    };
    res.json({ success: true, tickets, stats });
});

app.post("/api/admin/tickets/:id/reply", checkAdmin, (req, res) => {
    const id = req.params.id;
    const { message } = req.body;
    if (!message) return res.status(400).json({ success: false, message: "Falta mensaje" });
    const t = db.prepare("SELECT * FROM tickets WHERE id = ?").get(id);
    if (!t) return res.status(404).json({ success: false, message: "No encontrado" });
    const now = new Date().toISOString();
    const senderName = req.adminIsRoot ? "Soporte (Admin)" : (req.adminRow?.nickname || "Soporte");
    db.prepare(`INSERT INTO ticket_messages (ticket_id, sender_type, sender_name, message, created_at)
        VALUES (?, 'admin', ?, ?, ?)`)
      .run(id, senderName, message.trim(), now);
    db.prepare("UPDATE tickets SET updated_at = ?, status = 'pending', last_reply_by = 'admin' WHERE id = ?").run(now, id);
    if (t.user_key) io.to(`key:${t.user_key}`).emit("ticket-reply", { id, from: "admin" });
    res.json({ success: true });
});

app.post("/api/admin/tickets/:id/status", checkAdmin, (req, res) => {
    const { status } = req.body;
    if (!["open","pending","closed"].includes(status)) return res.status(400).json({ success: false, message: "Estado inválido" });
    const now = new Date().toISOString();
    const closedAt = status === "closed" ? now : null;
    db.prepare("UPDATE tickets SET status = ?, closed_at = ?, updated_at = ? WHERE id = ?").run(status, closedAt, now, req.params.id);
    io.emit("ticket-status", { id: req.params.id, status });
    res.json({ success: true });
});

app.post("/api/admin/tickets/:id/priority", checkAdmin, (req, res) => {
    const { priority } = req.body;
    if (!["low","normal","high","urgent"].includes(priority)) return res.status(400).json({ success: false, message: "Prioridad inválida" });
    db.prepare("UPDATE tickets SET priority = ? WHERE id = ?").run(priority, req.params.id);
    res.json({ success: true });
});

app.post("/api/admin/tickets/:id/delete", checkAdmin, (req, res) => {
    const canGrant = req.adminIsRoot || req.adminPermissions.includes("*") || req.adminPermissions.includes("manage_permissions");
    if (!canGrant) return res.status(403).json({ success: false, message: "Sin permiso" });
    db.prepare("DELETE FROM tickets WHERE id = ?").run(req.params.id);
    io.emit("ticket-deleted", { id: req.params.id });
    res.json({ success: true });
});

/* ============ IA ============ */
app.post("/api/ai/chat", rateLimit, async (req, res) => {
    const { mensaje, historial } = req.body;
    if (!mensaje) return res.status(400).json({ success: false, message: "Falta mensaje" });
    const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
    if (!GEMINI_API_KEY) return res.status(500).json({ success: false, message: "IA no configurada" });
    const juegos = db.prepare("SELECT name FROM games WHERE active = 1").all();
    const lista = juegos.map(j => j.name).join(", ") || "ninguno";
    const contexto = `Eres el asistente de OMELES GAMES. Responde en español. Productos: ${lista}.`;
    try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`;
        const body = {
            contents: [
                ...(historial || []).map(h => ({ role: h.tipo === "user" ? "user" : "model", parts: [{ text: h.texto }] })),
                { role: "user", parts: [{ text: mensaje }] }
            ],
            systemInstruction: { parts: [{ text: contexto }] },
            generationConfig: { temperature: 0.9, maxOutputTokens: 500 }
        };
        const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        if (!r.ok) return res.status(500).json({ success: false, message: "Error IA" });
        const d = await r.json();
        res.json({ success: true, respuesta: d.candidates?.[0]?.content?.parts?.[0]?.text || "Sin respuesta" });
    } catch { res.status(500).json({ success: false, message: "Error IA" }); }
});

/* ============ BACKUP ============ */
app.get("/api/admin/download-db", checkAdmin, (req, res) => {
    try { db.pragma("wal_checkpoint(TRUNCATE)"); } catch (e) {}
    const dbPath = process.env.DB_PATH || path.join(__dirname, "omeles.db");
    res.download(dbPath, `omeles-backup-${new Date().toISOString().slice(0,10)}.db`);
});

app.post("/api/admin/import-db", checkAdmin, (req, res) => {
    const { dbBase64 } = req.body;
    if (!dbBase64) return res.status(400).json({ success: false, message: "Falta archivo" });
    const tmpPath = "/tmp/omeles-import-" + Date.now() + ".db";
    try {
        fs.writeFileSync(tmpPath, Buffer.from(dbBase64, "base64"));
        let oldDb;
        try {
            oldDb = new Database(tmpPath, { readonly: true });
            oldDb.prepare("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1").get();
        } catch (e) {
            try { fs.unlinkSync(tmpPath); } catch {}
            return res.status(400).json({ success: false, message: "No es SQLite válido" });
        }
        let oldGames = [], oldKeys = [], oldUsers = [];
        try { oldGames = oldDb.prepare("SELECT * FROM games").all(); } catch {}
        try { oldKeys = oldDb.prepare("SELECT * FROM keys WHERE type NOT LIKE 'ADMIN%'").all(); } catch {}
        try { oldUsers = oldDb.prepare("SELECT * FROM users").all(); } catch {}
        oldDb.close();
        let gamesIn = 0, keysIn = 0, usersIn = 0;
        const tx = db.transaction(() => {
            for (const g of oldGames) {
                try {
                    const exists = db.prepare("SELECT id FROM games WHERE name = ?").get(g.name);
                    if (!exists) {
                        db.prepare(`INSERT INTO games (name, download, repair, password, image, active, created_at, type, description, content_url, content_file)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                          .run(g.name, g.download || "", g.repair || "", g.password || "", g.image || "", g.active || 1,
                               g.created_at || new Date().toISOString(), g.type || "game", g.description || "", g.content_url || "", g.content_file || "");
                        gamesIn++;
                    }
                } catch (e) {}
            }
            for (const k of oldKeys) {
                try {
                    const exists = db.prepare("SELECT id FROM keys WHERE key = ?").get(k.key);
                    if (!exists) {
                        db.prepare(`INSERT INTO keys (key, type, nickname, created_at, expires_at, active, use_count, last_ip, last_used_at, allowed_games, permissions, massive, game_mode)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                          .run(k.key, k.type, k.nickname || "", k.created_at, k.expires_at, k.active, k.use_count || 0,
                               k.last_ip || null, k.last_used_at || null, k.allowed_games || null, k.permissions || null,
                               k.massive || 0, k.game_mode || "all");
                        keysIn++;
                    }
                } catch (e) {}
            }
            for (const u of oldUsers) {
                try {
                    const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(u.username);
                    if (!exists) {
                        let keyId = u.key_id;
                        if (u.key_value) {
                            const kRow = db.prepare("SELECT id FROM keys WHERE key = ?").get(u.key_value);
                            if (kRow) keyId = kRow.id;
                        }
                        if (keyId) {
                            db.prepare(`INSERT INTO users (username, password_hash, key_id, created_at, last_login, plain_password, pinned)
                                VALUES (?, ?, ?, ?, ?, ?, ?)`)
                              .run(u.username, u.password_hash, keyId, u.created_at, u.last_login || null, u.plain_password || "", u.pinned || 0);
                            usersIn++;
                        }
                    }
                } catch (e) {}
            }
        });
        tx();
        try { fs.unlinkSync(tmpPath); } catch {}
        io.emit("games-updated", { action: "import" });
        res.json({ success: true, imported: { games: gamesIn, keys: keysIn, users: usersIn } });
    } catch (e) {
        try { fs.unlinkSync(tmpPath); } catch {}
        res.status(500).json({ success: false, message: "Error: " + e.message });
    }
});

server.listen(PORT, "0.0.0.0", () => {
    console.log(`\n✅ OMELES GAMES en puerto ${PORT}`);
    console.log(`🔑 Root Admin: ${ADMIN_KEY}`);
    console.log(`📂 Uploads: ${UPLOADS_DIR}\n`);
});
