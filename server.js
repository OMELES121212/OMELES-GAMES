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

// ======================================================
// HEALTH CHECK
// ======================================================
app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok", connections: io.engine.clientsCount });
});

// ======================================================
// RATE LIMITING
// ======================================================
const intentos = new Map();
function rateLimit(req, res, next) {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const ahora = Date.now();
    const datos = intentos.get(ip) || { count: 0, reset: ahora + 60000 };
    if (ahora > datos.reset) {
        datos.count = 0;
        datos.reset = ahora + 60000;
    }
    datos.count++;
    intentos.set(ip, datos);
    if (datos.count > 20) {
        return res.status(429).json({ success: false, message: "Demasiados intentos." });
    }
    next();
}

// ======================================================
// MIDDLEWARE ADMIN
// - Acepta ADMIN_KEY del entorno
// - Acepta keys ADMIN_* de la BD (registrando uso)
// ======================================================
function checkAdmin(req, res, next) {
    const key = req.headers["x-admin-key"];

    // 1. ADMIN_KEY maestra del entorno
    if (key === ADMIN_KEY) {
        return next();
    }

    // 2. Keys ADMIN guardadas en BD
    const row = db.prepare(
        "SELECT * FROM keys WHERE key = ? AND type LIKE 'ADMIN%'"
    ).get(key);

    if (!row) {
        return res.status(401).json({ success: false, message: "Admin Key incorrecta" });
    }

    if (row.expires_at && new Date(row.expires_at) <= new Date()) {
        db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(row.id);
        return res.status(401).json({ success: false, message: "Admin Key expirada" });
    }

    if (!row.active) {
        return res.status(401).json({ success: false, message: "Admin Key revocada" });
    }

    // 📌 REGISTRAR USO
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "?";
    const uses = (row.use_count || 0) + 1;
    db.prepare(`
        UPDATE keys 
        SET last_ip = ?, last_used_at = ?, use_count = ? 
        WHERE id = ?
    `).run(ip, new Date().toISOString(), uses, row.id);

    return next();
}

// ======================================================
// SOCKET.IO - Autenticación
// ======================================================
io.use((socket, next) => {
    const key = socket.handshake.auth.key;
    if (key) {
        socket.data.adminKey = key;
    }
    next();
});

io.on("connection", (socket) => {
    console.log(`🔌 Cliente conectado: ${socket.id} | AdminKey: ${socket.data.adminKey ? "sí" : "no"}`);
});

// ======================================================
// LOGIN CLIENTE
// ======================================================
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

    res.json({ success: true, type: row.type });
});

// ======================================================
// JUEGOS (cliente)
// ======================================================
app.get("/api/games", (req, res) => {
    const games = db.prepare("SELECT * FROM games WHERE active = 1 ORDER BY id DESC").all();
    res.json({ success: true, games });
});

// ======================================================
// KEYS (admin)
// ======================================================
app.get("/api/admin/keys", checkAdmin, (req, res) => {
    const keys = db.prepare("SELECT * FROM keys ORDER BY id DESC").all();
    res.json({ success: true, keys });
});

app.post("/api/keys", checkAdmin, (req, res) => {
    const { type } = req.body;

    const validos = [
        "24H", "7D", "30D", "LIFETIME", "ONE_USE",
        "ADMIN", "ADMIN_24H", "ADMIN_7D", "ADMIN_30D", "ADMIN_ONE_USE", "ADMIN_LIFETIME"
    ];

    if (!validos.includes(type)) {
        return res.status(400).json({ success: false, message: "Tipo inválido" });
    }

    const rand = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    const keyStr = `OMELES-${rand()}-${rand()}`;
    const now = new Date();
    let expires = null;

    if (type === "24H" || type === "ADMIN_24H") {
        expires = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
    }
    if (type === "7D" || type === "ADMIN_7D") {
        expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
    }
    if (type === "30D" || type === "ADMIN_30D") {
        expires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();
    }

    db.prepare(`INSERT INTO keys (key, type, created_at, expires_at, active) VALUES (?, ?, ?, ?, 1)`)
      .run(keyStr, type, now.toISOString(), expires);

    res.json({ success: true, key: keyStr });
});

app.post("/api/admin/update-key-nickname", checkAdmin, (req, res) => {
    const { id, nickname } = req.body;
    db.prepare("UPDATE keys SET nickname = ? WHERE id = ?").run(nickname || "", id);
    res.json({ success: true });
});

// REVOCAR KEY (con kick en tiempo real)
app.post("/api/admin/revoke-key", checkAdmin, (req, res) => {
    const id = req.body.id;

    const row = db.prepare("SELECT key FROM keys WHERE id = ?").get(id);

    db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(id);

    if (row) {
        io.emit("admin-key-revoked", { key: row.key });
        console.log(`🚫 Key revocada y emitida: ${row.key}`);
    }

    res.json({ success: true });
});

// ELIMINAR KEY (con kick en tiempo real)
app.post("/api/admin/delete-key", checkAdmin, (req, res) => {
    const id = req.body.id;

    const row = db.prepare("SELECT key FROM keys WHERE id = ?").get(id);

    db.prepare("DELETE FROM keys WHERE id = ?").run(id);

    if (row) {
        io.emit("admin-key-revoked", { key: row.key });
    }

    res.json({ success: true });
});

// ======================================================
// JUEGOS (admin)
// ======================================================
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

// ======================================================
// ARRANCAR
// ======================================================
server.listen(PORT, "0.0.0.0", () => {
    console.log(`\n✅ OMELES GAMES en puerto ${PORT}`);
    console.log(`🔑 Admin Key: ${ADMIN_KEY}\n`);
});
