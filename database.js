const sqlite3 = require('sqlite3').verbose();
const path = require('path');

// Cria ou abre o ficheiro da base de dados SQLite
const dbPath = path.resolve(__dirname, 'gatekeeper.db');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('Erro ao conectar ao banco de dados SQLite:', err.message);
  } else {
    console.log('[SQLite] Conectado ao banco de dados local com sucesso.');
  }
});

module.exports = db;