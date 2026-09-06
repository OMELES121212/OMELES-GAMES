const Database = require("better-sqlite3");

const db = new Database("omeles_games.db");

// =========================
// KEYS DE CLIENTES
// =========================

db.prepare(`
    CREATE TABLE IF NOT EXISTS keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        active INTEGER DEFAULT 1
    )
`).run();


// =========================
// JUEGOS
// =========================

db.prepare(`
    CREATE TABLE IF NOT EXISTS games (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        download TEXT,
        repair TEXT,
        password TEXT,
        active INTEGER DEFAULT 1
    )
`).run();


console.log("Base de datos OMELES GAMES preparada.");

module.exports = db;