const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
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

app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.static(path.join(__dirname, "public")));

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
    if (d.count > 40) return res.status(429).json({ success: false, message: "Demasiados intentos." });
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

/* ============================================================
   HELPER: Resolver juegos permitidos según game_mode
============================================================ */
function resolverJuegosPermitidos(row) {
    const mode = row.game_mode || "all";
    const allActive = db.prepare("SELECT * FROM games WHERE active = 1 ORDER BY id DESC").all();

    if (mode === "none") return [];
    if (mode === "all") return allActive;

    let ids = [];
    if (row.allowed_games) {
        try { ids = JSON.parse(row.allowed_games); } catch { ids = []; }
    }

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
   REGISTRO DE USUARIO
============================================================ */
app.post("/api/register", rateLimit, (req, res) => {
    const { key, username, password } = req.body;

    if (!key || !username || !password)
        return res.status(400).json({ success: false, message: "Rellena todos los campos" });
    if (username.length < 3 || username.length > 20)
        return res.status(400).json({ success: false, message: "Usuario: entre 3 y 20 caracteres" });
    if (!/^[a-zA-Z0-9_.-]+$/.test(username))
        return res.status(400).json({ success: false, message: "Usuario: solo letras, números, . _ -" });
    if (password.length < 4)
        return res.status(400).json({ success: false, message: "Contraseña: mínimo 4 caracteres" });

    const keyRow = db.prepare("SELECT * FROM keys WHERE key = ?").get(key.trim());
    if (!keyRow) return res.status(401).json({ success: false, message: "Key no válida" });
    if (!keyRow.active) return res.status(401).json({ success: false, message: "Key revocada o ya usada" });
    if (keyRow.expires_at && new Date(keyRow.expires_at) <= new Date()) {
        db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(keyRow.id);
        return res.status(401).json({ success: false, message: "Key expirada" });
    }

    const yaAsignada = db.prepare("SELECT id, username FROM users WHERE key_id = ?").get(keyRow.id);
    if (yaAsignada)
        return res.status(409).json({ success: false, message: `Esta key ya está registrada por "${yaAsignada.username}"` });

    const yaExiste = db.prepare("SELECT id FROM users WHERE username = ?").get(username.trim());
    if (yaExiste)
        return res.status(409).json({ success: false, message: "Ese nombre de usuario ya está en uso" });

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
        const allowed = keyRow.game_mode === "all"
            ? null
            : juegosPermitidos.map(g => g.id);

        res.json({ success: true, user: { username: username.trim() }, key: keyRow.key, type: keyRow.type, allowed });
    } catch (e) {
        console.error(e);
        res.status(500).json({ success: false, message: "Error al registrar" });
    }
});

/* ============================================================
   LOGIN CON USUARIO + CONTRASEÑA
============================================================ */
app.post("/api/login-user", rateLimit, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password)
        return res.status(400).json({ success: false, message: "Rellena usuario y contraseña" });

    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim());
    if (!user) return res.status(401).json({ success: false, message: "Usuario o contraseña incorrectos" });
    if (!verifyPassword(password, user.password_hash))
        return res.status(401).json({ success: false, message: "Usuario o contraseña incorrectos" });

    const key = db.prepare("SELECT * FROM keys WHERE id = ?").get(user.key_id);
    if (!key) return res.status(401).json({ success: false, message: "Key asociada no encontrada" });
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

/* ============================================================
   LOGIN DIRECTO CON KEY
============================================================ */
app.post("/api/login", rateLimit, (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ success: false, message: "Falta la key" });

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

/* ============ INFO ADMIN ============ */
app.get("/api/admin/me", checkAdmin, (req, res) => {
    res.json({
        success: true,
        isRoot: req.adminIsRoot,
        permissions: req.adminPermissions,
        nickname: req.adminIsRoot ? "Root Admin" : (req.adminRow?.nickname || "Admin")
    });
});

/* ============ JUEGOS DEL USUARIO ============ */
app.get("/api/games", (req, res) => {
    const key = req.headers["x-user-key"];
    if (!key) return res.status(401).json({ success: false, message: "Falta la key" });

    const row = db.prepare("SELECT * FROM keys WHERE key = ?").get(key);
    if (!row) return res.status(401).json({ success: false, message: "Key no válida" });

    const games = resolverJuegosPermitidos(row);
    res.json({ success: true, games });
});

/* ============ KEYS (admin) ============ */
app.get("/api/admin/keys", checkAdmin, (req, res) => {
    const keys = db.prepare("SELECT * FROM keys WHERE key != ? ORDER BY id DESC").all(ADMIN_KEY);
    res.json({ success: true, keys });
});

app.post("/api/keys", checkAdmin, (req, res) => {
    const { type, gameId, gameIds, permissions, massive, count, gameMode } = req.body;
    const validos = ["24H","7D","30D","LIFETIME","ONE_USE",
        "ADMIN","ADMIN_24H","ADMIN_7D","ADMIN_30D","ADMIN_ONE_USE","ADMIN_LIFETIME"];
    if (!validos.includes(type)) return res.status(400).json({ success: false, message: "Tipo inválido" });

    let permsValue = null;
    if (type.startsWith("ADMIN")) {
        const canGrant = req.adminIsRoot || req.adminPermissions.includes("*") || req.adminPermissions.includes("manage_permissions");
        if (!canGrant) return res.status(403).json({ success: false, message: "Sin permiso" });
        permsValue = Array.isArray(permissions) ? JSON.stringify(permissions) : JSON.stringify(["*"]);
    }

    /* Modo de juegos */
    let mode = String(gameMode || "all").toLowerCase();
    if (!["all","none","whitelist","blacklist"].includes(mode)) mode = "all";

    let ids = [];
    if (Array.isArray(gameIds) && gameIds.length > 0) {
        ids = gameIds.map(Number).filter(n => Number.isFinite(n) && n > 0);
    } else if (gameId !== undefined && gameId !== null && gameId !== "") {
        const gid = Number(gameId);
        if (Number.isFinite(gid) && gid > 0) ids = [gid];
    }

    // Validar que los ids existen
    if (ids.length > 0) {
        const ph = ids.map(() => "?").join(",");
        const found = db.prepare(`SELECT id FROM games WHERE active = 1 AND id IN (${ph})`).all(...ids);
        if (found.length !== ids.length)
            return res.status(404).json({ success: false, message: "Algún juego no existe" });
    }

    // Para modo "all" o "none" ignoramos los ids
    let allowed_games = null;
    let gameIdPrefix = "";
    if (mode === "whitelist" || mode === "blacklist") {
        if (ids.length === 0 && mode === "whitelist") {
            // Sin juegos seleccionados en whitelist = no verá nada
            allowed_games = JSON.stringify([]);
        } else {
            allowed_games = JSON.stringify(ids);
        }
        // Prefijo solo si whitelist con 1 juego
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
        console.error("Error generando keys:", e);
        return res.status(500).json({ success: false, message: "Error al generar keys" });
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
    if (row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes tocar el Root Admin" });
    if (!row.type.startsWith("ADMIN")) return res.status(400).json({ success: false, message: "No es admin" });
    const value = Array.isArray(permissions) ? JSON.stringify(permissions) : JSON.stringify(["*"]);
    db.prepare("UPDATE keys SET permissions = ? WHERE id = ?").run(value, id);
    res.json({ success: true });
});

app.post("/api/admin/update-key-nickname", checkAdmin, (req, res) => {
    const { id, nickname } = req.body;
    const row = db.prepare("SELECT key FROM keys WHERE id = ?").get(id);
    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes tocar el Root Admin" });
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
        if (mode === "whitelist" || mode === "blacklist") {
            value = JSON.stringify(allowed.map(Number));
        } else {
            value = null;
        }
    }

    db.prepare("UPDATE keys SET allowed_games = ?, game_mode = ? WHERE id = ?").run(value, mode, id);

    const row2 = db.prepare("SELECT key FROM keys WHERE id = ?").get(id);
    if (row2) io.to(`key:${row2.key}`).emit("key-updated", { key: row2.key });

    res.json({ success: true });
});

app.post("/api/admin/revoke-key", checkAdmin, (req, res) => {
    const row = db.prepare("SELECT key, type FROM keys WHERE id = ?").get(req.body.id);
    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes revocar el Root Admin" });
    db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(req.body.id);
    if (row) io.emit("key-revoked", { key: row.key, type: row.type });
    res.json({ success: true });
});

app.post("/api/admin/delete-key", checkAdmin, (req, res) => {
    const row = db.prepare("SELECT key, type FROM keys WHERE id = ?").get(req.body.id);
    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes borrar el Root Admin" });
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
        SELECT u.id, u.username, u.created_at, u.last_login, u.key_id, u.plain_password,
               k.key as key_value, k.type as key_type, k.nickname as key_nickname,
               k.active as key_active, k.expires_at as key_expires
        FROM users u
        LEFT JOIN keys k ON u.key_id = k.id
        ORDER BY u.id DESC
    `).all();
    res.json({ success: true, users });
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
        return res.status(400).json({ success: false, message: "Contraseña mínimo 4 caracteres" });
    const hash = hashPassword(newPassword);
    db.prepare("UPDATE users SET password_hash = ?, plain_password = ? WHERE id = ?").run(hash, newPassword, id);
    res.json({ success: true });
});

/* ============ JUEGOS ============ */
app.get("/api/admin/games", checkAdmin, (req, res) => {
    const games = db.prepare("SELECT * FROM games ORDER BY id DESC").all();
    res.json({ success: true, games });
});

app.post("/api/games", checkAdmin, (req, res) => {
    const { name, download, repair, password, image } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Falta nombre" });
    db.prepare(`INSERT INTO games (name, download, repair, password, image, active, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)`)
      .run(name, download || "", repair || "", password || "", image || "", new Date().toISOString());
    io.emit("games-updated", { action: "create", name });
    res.json({ success: true });
});

app.post("/api/admin/update-game", checkAdmin, (req, res) => {
    const { id, name, download, repair, password, image } = req.body;
    db.prepare(`UPDATE games SET name = ?, download = ?, repair = ?, password = ?, image = ? WHERE id = ?`)
      .run(name, download, repair, password, image || "", id);
    io.emit("games-updated", { action: "update", name });
    res.json({ success: true });
});

app.post("/api/admin/delete-game", checkAdmin, (req, res) => {
    db.prepare("DELETE FROM games WHERE id = ?").run(req.body.id);
    io.emit("games-updated", { action: "delete" });
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
    const contexto = `Eres el asistente de OMELES GAMES. Responde en español. Juegos: ${lista}.`;

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

/* ============================================================
   BACKUP - EXPORTAR
============================================================ */
app.get("/api/admin/download-db", checkAdmin, (req, res) => {
    try {
        db.pragma("wal_checkpoint(TRUNCATE)");
        console.log("✅ Checkpoint WAL completado");
    } catch (e) {
        console.error("❌ Error en checkpoint:", e);
    }
    const dbPath = process.env.DB_PATH || path.join(__dirname, "omeles.db");
    console.log(`📥 Exportando DB desde: ${dbPath}`);
    res.download(dbPath, `omeles-backup-${new Date().toISOString().slice(0,10)}.db`);
});

/* ============================================================
   BACKUP - IMPORTAR
============================================================ */
app.post("/api/admin/import-db", checkAdmin, (req, res) => {
    const { dbBase64 } = req.body;
    if (!dbBase64) return res.status(400).json({ success: false, message: "Falta el archivo" });

    const tmpPath = "/tmp/omeles-import-" + Date.now() + ".db";
    try {
        fs.writeFileSync(tmpPath, Buffer.from(dbBase64, "base64"));

        let oldDb;
        try {
            oldDb = new Database(tmpPath, { readonly: true });
            oldDb.prepare("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1").get();
        } catch (e) {
            try { fs.unlinkSync(tmpPath); } catch {}
            return res.status(400).json({ success: false, message: "El archivo no es una DB SQLite válida" });
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
                        db.prepare(`INSERT INTO games (name, download, repair, password, image, active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
                          .run(g.name, g.download || "", g.repair || "", g.password || "", g.image || "", g.active || 1, g.created_at || new Date().toISOString());
                        gamesIn++;
                    }
                } catch (e) { console.error("Error importando juego:", g.name, e.message); }
            }

            for (const k of oldKeys) {
                try {
                    const exists = db.prepare("SELECT id FROM keys WHERE key = ?").get(k.key);
                    if (!exists) {
                        db.prepare(`INSERT INTO keys (key, type, nickname, created_at, expires_at, active, use_count, last_ip, last_used_at, allowed_games, permissions, massive, game_mode)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                          .run(k.key, k.type, k.nickname || "", k.created_at, k.expires_at, k.active, k.use_count || 0,
                               k.last_ip || null, k.last_used_at || null,
                               k.allowed_games || null, k.permissions || null, k.massive || 0,
                               k.game_mode || "all");
                        keysIn++;
                    }
                } catch (e) { console.error("Error importando key:", k.key, e.message); }
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
                            db.prepare(`INSERT INTO users (username, password_hash, key_id, created_at, last_login, plain_password)
                                VALUES (?, ?, ?, ?, ?, ?)`)
                              .run(u.username, u.password_hash, keyId, u.created_at, u.last_login || null, u.plain_password || "");
                            usersIn++;
                        }
                    }
                } catch (e) { console.error("Error importando usuario:", u.username, e.message); }
            }
        });

        tx();

        try { fs.unlinkSync(tmpPath); } catch {}

        console.log(`✅ Import completado: ${gamesIn} juegos, ${keysIn} keys, ${usersIn} usuarios`);
        io.emit("games-updated", { action: "import" });

        res.json({
            success: true,
            imported: { games: gamesIn, keys: keysIn, users: usersIn },
            message: `Importados ${gamesIn} juegos, ${keysIn} keys, ${usersIn} usuarios`
        });
    } catch (e) {
        console.error("Error importando DB:", e);
        try { fs.unlinkSync(tmpPath); } catch {}
        res.status(500).json({ success: false, message: "Error procesando el archivo: " + e.message });
    }
});

server.listen(PORT, "0.0.0.0", () => {
    console.log(`\n✅ OMELES GAMES en puerto ${PORT}`);
    console.log(`🔑 Root Admin: ${ADMIN_KEY}\n`);
});
