const Database = require("better-sqlite3");
const path = require("path");
const fs = require("fs");
const { DatabaseSync } = require("node:sqlite");

const DB_PATH = process.env.DB_PATH || path.join(__dirname, "omeles_games.db");

const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
}

const db = new DatabaseSync(DB_PATH);

// =========================
// TABLA KEYS
// =========================
db.prepare(`
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        nickname TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        expires_at TEXT,
        active INTEGER DEFAULT 1,
        last_ip TEXT,
        last_used_at TEXT,
        use_count INTEGER DEFAULT 0
    )
`).run();

// =========================
// TABLA JUEGOS
// =========================
db.prepare(`
    CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        download TEXT,
        repair TEXT,
        password TEXT,
        image TEXT DEFAULT '',
        active INTEGER DEFAULT 1,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
`).run();

// =========================
// MIGRACIÓN: añadir columna image si la BD ya existía
// =========================
try {
    db.prepare("ALTER TABLE games ADD COLUMN image TEXT DEFAULT ''").run();
    console.log("✅ Columna 'image' añadida a games");
} catch (e) {
    // Ya existía, ignorar
}

console.log(`✅ Base de datos OMELES GAMES lista en: ${DB_PATH}`);
module.exports = db;
