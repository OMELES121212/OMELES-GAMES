const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { Server } = require("socket.io");
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
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok", connections: io.engine.clientsCount });
});

const intentos = new Map();
function rateLimit(req, res, next) {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const ahora = Date.now();
    const datos = intentos.get(ip) || { count: 0, reset: ahora + 60000 };
    if (ahora > datos.reset) { datos.count = 0; datos.reset = ahora + 60000; }
    datos.count++;
    intentos.set(ip, datos);
    if (datos.count > 30) return res.status(429).json({ success: false, message: "Demasiados intentos." });
    next();
}

/* ============================================================
   MIDDLEWARE ADMIN
   Añade req.adminIsRoot y req.adminPermissions
============================================================ */
function checkAdmin(req, res, next) {
    const key = req.headers["x-admin-key"];

    // Root admin (desde variable de entorno)
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
    const uses = (row.use_count || 0) + 1;
    db.prepare(`UPDATE keys SET last_ip = ?, last_used_at = ?, use_count = ? WHERE id = ?`)
      .run(ip, new Date().toISOString(), uses, row.id);

    let perms = [];
    try { perms = row.permissions ? JSON.parse(row.permissions) : []; } catch { perms = []; }
    req.adminIsRoot = false;
    req.adminPermissions = perms;
    req.adminRow = row;

    return next();
}

/* ============================================================
   SOCKET
============================================================ */
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
   LOGIN USUARIO
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

    let allowed = null;
    if (row.allowed_games) {
        try { allowed = JSON.parse(row.allowed_games); } catch { allowed = []; }
    }

    res.json({ success: true, type: row.type, allowed });
});

/* ============================================================
   INFO DEL ADMIN ACTUAL (login del panel)
============================================================ */
app.get("/api/admin/me", checkAdmin, (req, res) => {
    res.json({
        success: true,
        isRoot: req.adminIsRoot,
        permissions: req.adminPermissions,
        nickname: req.adminIsRoot ? "Root Admin" : (req.adminRow?.nickname || "Admin")
    });
});

/* ============================================================
   JUEGOS DEL USUARIO
============================================================ */
app.get("/api/games", (req, res) => {
    const key = req.headers["x-user-key"];
    if (!key) return res.status(401).json({ success: false, message: "Falta la key de usuario" });

    const row = db.prepare("SELECT * FROM keys WHERE key = ?").get(key);
    if (!row) return res.status(401).json({ success: false, message: "Key no válida" });

    let games;
    if (row.allowed_games) {
        let ids;
        try { ids = JSON.parse(row.allowed_games); } catch { ids = []; }
        if (!Array.isArray(ids) || ids.length === 0) return res.json({ success: true, games: [] });
        const placeholders = ids.map(() => "?").join(",");
        games = db.prepare(`SELECT * FROM games WHERE active = 1 AND id IN (${placeholders}) ORDER BY id DESC`).all(...ids);
    } else {
        games = db.prepare("SELECT * FROM games WHERE active = 1 ORDER BY id DESC").all();
    }
    res.json({ success: true, games });
});

/* ============================================================
   LISTAR KEYS (oculta la root)
============================================================ */
app.get("/api/admin/keys", checkAdmin, (req, res) => {
    const keys = db.prepare("SELECT * FROM keys WHERE key != ? ORDER BY id DESC").all(ADMIN_KEY);
    res.json({ success: true, keys });
});

/* ============================================================
   CREAR KEY (con permisos para admins)
============================================================ */
app.post("/api/keys", checkAdmin, (req, res) => {
    const { type, gameId, permissions } = req.body;

    const validos = [
        "24H", "7D", "30D", "LIFETIME", "ONE_USE",
        "ADMIN", "ADMIN_24H", "ADMIN_7D", "ADMIN_30D", "ADMIN_ONE_USE", "ADMIN_LIFETIME"
    ];

    if (!validos.includes(type)) return res.status(400).json({ success: false, message: "Tipo inválido" });

    // Permisos: solo si es admin y el que crea tiene permiso
    let permsValue = null;
    const esAdminType = type.startsWith("ADMIN");
    if (esAdminType) {
        const canGrant = req.adminIsRoot || req.adminPermissions.includes("*") || req.adminPermissions.includes("manage_permissions");
        if (!canGrant) return res.status(403).json({ success: false, message: "No tienes permiso para crear admins" });

        if (Array.isArray(permissions)) {
            permsValue = JSON.stringify(permissions);
        } else {
            // Por defecto: todos los permisos
            permsValue = JSON.stringify(["*"]);
        }
    }

    let allowed_games = null;
    let gameIdPrefix = "";

    if (gameId !== undefined && gameId !== null && gameId !== "") {
        const gid = Number(gameId);
        if (!Number.isFinite(gid) || gid <= 0) return res.status(400).json({ success: false, message: "ID de juego inválido" });
        const game = db.prepare("SELECT id FROM games WHERE id = ? AND active = 1").get(gid);
        if (!game) return res.status(404).json({ success: false, message: "Juego no encontrado" });
        gameIdPrefix = `${gid}-`;
        allowed_games = JSON.stringify([gid]);
    }

    const rand = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    const keyStr = `OMELES-${gameIdPrefix}${rand()}-${rand()}`;
    const now = new Date();
    let expires = null;

    if (type === "24H" || type === "ADMIN_24H") expires = new Date(now.getTime() + 24*60*60*1000).toISOString();
    if (type === "7D" || type === "ADMIN_7D") expires = new Date(now.getTime() + 7*24*60*60*1000).toISOString();
    if (type === "30D" || type === "ADMIN_30D") expires = new Date(now.getTime() + 30*24*60*60*1000).toISOString();

    db.prepare(`INSERT INTO keys (key, type, created_at, expires_at, active, allowed_games, permissions) VALUES (?, ?, ?, ?, 1, ?, ?)`)
      .run(keyStr, type, now.toISOString(), expires, allowed_games, permsValue);

    res.json({ success: true, key: keyStr, gameId: gameIdPrefix ? Number(gameId) : null });
});

/* ============================================================
   ACTUALIZAR PERMISOS DE UN ADMIN
============================================================ */
app.post("/api/admin/update-key-permissions", checkAdmin, (req, res) => {
    const { id, permissions } = req.body;

    const canGrant = req.adminIsRoot || req.adminPermissions.includes("*") || req.adminPermissions.includes("manage_permissions");
    if (!canGrant) return res.status(403).json({ success: false, message: "No tienes permiso" });

    const row = db.prepare("SELECT * FROM keys WHERE id = ?").get(id);
    if (!row) return res.status(404).json({ success: false, message: "Key no encontrada" });
    if (row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes modificar el Root Admin" });
    if (!row.type.startsWith("ADMIN")) return res.status(400).json({ success: false, message: "Esta key no es de admin" });

    const value = Array.isArray(permissions) ? JSON.stringify(permissions) : JSON.stringify(["*"]);
    db.prepare("UPDATE keys SET permissions = ? WHERE id = ?").run(value, id);
    res.json({ success: true });
});

/* ============================================================
   MOTE
============================================================ */
app.post("/api/admin/update-key-nickname", checkAdmin, (req, res) => {
    const { id, nickname } = req.body;

    const row = db.prepare("SELECT key FROM keys WHERE id = ?").get(id);
    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes modificar el Root Admin" });

    db.prepare("UPDATE keys SET nickname = ? WHERE id = ?").run(nickname || "", id);
    res.json({ success: true });
});

/* ============================================================
   JUEGOS POR KEY
============================================================ */
app.get("/api/admin/key-games/:id", checkAdmin, (req, res) => {
    const id = req.params.id;
    const row = db.prepare("SELECT allowed_games FROM keys WHERE id = ?").get(id);
    if (!row) return res.status(404).json({ success: false, message: "Key no encontrada" });

    const allGames = db.prepare("SELECT id, name FROM games WHERE active = 1 ORDER BY name").all();
    let allowed = null;
    if (row.allowed_games) { try { allowed = JSON.parse(row.allowed_games); } catch { allowed = []; } }
    res.json({ success: true, allowed, allGames });
});

app.post("/api/admin/update-key-games", checkAdmin, (req, res) => {
    const { id, allowed } = req.body;
    if (!id) return res.status(400).json({ success: false, message: "Falta id" });

    let value = null;
    if (Array.isArray(allowed)) {
        const totalGames = db.prepare("SELECT COUNT(*) as c FROM games WHERE active = 1").get().c;
        if (allowed.length === totalGames) value = null;
        else value = JSON.stringify(allowed.map(Number));
    }

    db.prepare("UPDATE keys SET allowed_games = ? WHERE id = ?").run(value, id);

    const row = db.prepare("SELECT key FROM keys WHERE id = ?").get(id);
    if (row) io.to(`key:${row.key}`).emit("key-updated", { key: row.key });
    res.json({ success: true });
});

/* ============================================================
   REVOCAR / ELIMINAR
============================================================ */
app.post("/api/admin/revoke-key", checkAdmin, (req, res) => {
    const id = req.body.id;
    const row = db.prepare("SELECT key, type FROM keys WHERE id = ?").get(id);

    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes revocar el Root Admin" });

    db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(id);
    if (row) io.emit("key-revoked", { key: row.key, type: row.type });
    res.json({ success: true });
});

app.post("/api/admin/delete-key", checkAdmin, (req, res) => {
    const id = req.body.id;
    const row = db.prepare("SELECT key, type FROM keys WHERE id = ?").get(id);

    if (row && row.key === ADMIN_KEY) return res.status(403).json({ success: false, message: "No puedes eliminar el Root Admin" });

    db.prepare("DELETE FROM keys WHERE id = ?").run(id);
    if (row) io.emit("key-revoked", { key: row.key, type: row.type });
    res.json({ success: true });
});

/* ============================================================
   JUEGOS
============================================================ */
app.get("/api/admin/games", checkAdmin, (req, res) => {
    const games = db.prepare("SELECT * FROM games ORDER BY id DESC").all();
    res.json({ success: true, games });
});

app.post("/api/games", checkAdmin, (req, res) => {
    const { name, download, repair, password, image } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Falta el nombre" });

    db.prepare(`INSERT INTO games (name, download, repair, password, image, active) VALUES (?, ?, ?, ?, ?, 1)`)
      .run(name, download || "", repair || "", password || "", image || "");

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

/* ============================================================
   IA
============================================================ */
app.post("/api/ai/chat", rateLimit, async (req, res) => {
    const { mensaje, historial } = req.body;
    if (!mensaje) return res.status(400).json({ success: false, message: "Falta el mensaje" });

    const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
    if (!GEMINI_API_KEY) return res.status(500).json({ success: false, message: "IA no configurada" });

    const juegos = db.prepare("SELECT name FROM games WHERE active = 1").all();
    const listaNombres = juegos.map(j => j.name).join(", ") || "ninguno";
    const contexto = `Eres el asistente de OMELES GAMES. Respondes en español. Hay ${juegos.length} juegos: ${listaNombres}. Sé conciso.`;

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
        const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
        if (!response.ok) return res.status(500).json({ success: false, message: "Error IA" });
        const data = await response.json();
        const texto = data.candidates?.[0]?.content?.parts?.[0]?.text || "Sin respuesta.";
        res.json({ success: true, respuesta: texto });
    } catch (e) {
        res.status(500).json({ success: false, message: "Error IA" });
    }
});

server.listen(PORT, "0.0.0.0", () => {
    console.log(`\n✅ OMELES GAMES en puerto ${PORT}`);
    console.log(`🔑 Root Admin: ${ADMIN_KEY}`);
    console.log("");
});
