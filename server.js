const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { Server } = require("socket.io");
const db = require("./database");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = 3000;

// 🔐 CAMBIA ESTA CLAVE POR LA TUYA (Admin Key)
const ADMIN_KEY = "OMELES-ADMIN-2026";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ======================================================
// RATE LIMITING (anti fuerza bruta en /api/login)
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
        return res.status(429).json({ success: false, message: "Demasiados intentos. Espera 1 minuto." });
    }
    next();
}

// ======================================================
// MIDDLEWARE ADMIN
// ======================================================
function checkAdmin(req, res, next) {
    const key = req.headers["x-admin-key"];
    if (key !== ADMIN_KEY) {
        return res.status(401).json({ success: false, message: "Admin Key incorrecta" });
    }
    next();
}

// ======================================================
// SOCKET.IO - TIEMPO REAL
// ======================================================
io.on("connection", (socket) => {
    console.log(`🔌 Cliente conectado: ${socket.id}`);
    socket.on("disconnect", () => {
        console.log(`❌ Cliente desconectado: ${socket.id}`);
    });
});

// ======================================================
// LOGIN CLIENTE CON KEY
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
    const active = row.type === "ONE_USE" ? 0 : 1;

    db.prepare(`
        UPDATE keys SET last_ip = ?, last_used_at = ?, use_count = ?, active = ?
        WHERE id = ?
    `).run(ip, new Date().toISOString(), uses, active, row.id);

    res.json({ success: true, type: row.type });
});

// ======================================================
// CLIENTE: LISTAR JUEGOS
// ======================================================
app.get("/api/games", (req, res) => {
    const games = db.prepare("SELECT * FROM games WHERE active = 1 ORDER BY id DESC").all();
    res.json({ success: true, games });
});

// ======================================================
// ADMIN: LISTAR KEYS
// ======================================================
app.get("/api/admin/keys", checkAdmin, (req, res) => {
    const keys = db.prepare("SELECT * FROM keys ORDER BY id DESC").all();
    res.json({ success: true, keys });
});

// ======================================================
// ADMIN: CREAR KEY
// ======================================================
app.post("/api/keys", checkAdmin, (req, res) => {
    const { type } = req.body;
    const validos = ["24H", "7D", "30D", "LIFETIME", "ONE_USE", "ADMIN"];
    if (!validos.includes(type)) return res.status(400).json({ success: false, message: "Tipo inválido" });

    const rand = () => crypto.randomBytes(3).toString("hex").toUpperCase();
    const keyStr = `OMELES-${rand()}-${rand()}`;

    const now = new Date();
    let expires = null;
    if (type === "24H") expires = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
    if (type === "7D") expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000).toISOString();
    if (type === "30D") expires = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000).toISOString();

    db.prepare(`
        INSERT INTO keys (key, type, created_at, expires_at, active)
        VALUES (?, ?, ?, ?, 1)
    `).run(keyStr, type, now.toISOString(), expires);

    res.json({ success: true, key: keyStr });
});

// ======================================================
// ADMIN: EDITAR MOTE DE KEY
// ======================================================
app.post("/api/admin/update-key-nickname", checkAdmin, (req, res) => {
    const { id, nickname } = req.body;
    db.prepare("UPDATE keys SET nickname = ? WHERE id = ?").run(nickname || "", id);
    res.json({ success: true });
});

// ======================================================
// ADMIN: REVOCAR KEY
// ======================================================
app.post("/api/admin/revoke-key", checkAdmin, (req, res) => {
    db.prepare("UPDATE keys SET active = 0 WHERE id = ?").run(req.body.id);
    res.json({ success: true });
});

// ======================================================
// ADMIN: ELIMINAR KEY
// ======================================================
app.post("/api/admin/delete-key", checkAdmin, (req, res) => {
    db.prepare("DELETE FROM keys WHERE id = ?").run(req.body.id);
    res.json({ success: true });
});

// ======================================================
// ADMIN: LISTAR JUEGOS
// ======================================================
app.get("/api/admin/games", checkAdmin, (req, res) => {
    const games = db.prepare("SELECT * FROM games ORDER BY id DESC").all();
    res.json({ success: true, games });
});

// ======================================================
// ADMIN: CREAR JUEGO (EMITE TIEMPO REAL)
// ======================================================
app.post("/api/games", checkAdmin, (req, res) => {
    const { name, download, repair, password } = req.body;
    if (!name) return res.status(400).json({ success: false, message: "Falta el nombre" });

    db.prepare(`
        INSERT INTO games (name, download, repair, password, active)
        VALUES (?, ?, ?, ?, 1)
    `).run(name, download || "", repair || "", password || "");

    // 🔴 EMITIR A TODOS LOS CLIENTES
    io.emit("games-updated", { action: "create", name });

    res.json({ success: true });
});

// ======================================================
// ADMIN: EDITAR JUEGO (EMITE TIEMPO REAL)
// ======================================================
app.post("/api/admin/update-game", checkAdmin, (req, res) => {
    const { id, name, download, repair, password } = req.body;
    db.prepare(`
        UPDATE games SET name = ?, download = ?, repair = ?, password = ?
        WHERE id = ?
    `).run(name, download, repair, password, id);

    io.emit("games-updated", { action: "update", name });

    res.json({ success: true });
});

// ======================================================
// ADMIN: ELIMINAR JUEGO (EMITE TIEMPO REAL)
// ======================================================
app.post("/api/admin/delete-game", checkAdmin, (req, res) => {
    db.prepare("DELETE FROM games WHERE id = ?").run(req.body.id);

    io.emit("games-updated", { action: "delete" });

    res.json({ success: true });
});

// ======================================================
// ARRANCAR
// ======================================================
server.listen(PORT, () => {
    console.log(`\n✅ OMELES GAMES en http://localhost:${PORT}`);
    console.log(`🔑 Admin Key: ${ADMIN_KEY}\n`);
});