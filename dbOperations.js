const db = require("./database");

function findUserByEmail(email) {
  return new Promise((resolve, reject) => {
    const query = `SELECT * FROM usuarios WHERE email = ?`;
    db.get(query, [email], (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
}

function createUser(email, senhaHash) {
  return new Promise((resolve, reject) => {
    const query = `INSERT INTO usuarios (email, senha_hash, tentativas_falhas) VALUES (?, ?, 0)`;
    db.run(query, [email, senhaHash], function (err) {
      if (err) reject(err);
      else resolve(this.lastID);
    });
  });
}

function incrementFailedAttempts(userId, attempts) {
  return new Promise((resolve, reject) => {
    const query = `UPDATE usuarios SET tentativas_falhas = ? WHERE id = ?`;
    db.run(query, [attempts, userId], (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function lockUserAccount(userId, blockedUntil) {
  return new Promise((resolve, reject) => {
    const query = `UPDATE usuarios SET tentativas_falhas = 3, bloqueado_ate = ? WHERE id = ?`;
    db.run(query, [blockedUntil, userId], (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function resetUserLock(userId) {
  return new Promise((resolve, reject) => {
    const query = `UPDATE usuarios SET tentativas_falhas = 0, bloqueado_ate = NULL WHERE id = ?`;
    db.run(query, [userId], (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

function createAuditLog({
  ipOrigem,
  horaDia,
  nivelRisco,
  acaoExecutada,
  usuarioId,
}) {
  return new Promise((resolve, reject) => {
    const query = `
      INSERT INTO logs_auditoria (timestamp, ip_origem, hora_dia, nivel_risco, acao_executada, usuario_id)
      VALUES (DATETIME('now'), ?, ?, ?, ?, ?)
    `;
    db.run(
      query,
      [ipOrigem, horaDia, nivelRisco, acaoExecutada, usuarioId],
      function (err) {
        if (err) reject(err);
        else resolve(this.lastID);
      },
    );
  });
}

function getUserLoginHistory(usuarioId, limit = 50) {
  return new Promise((resolve, reject) => {
    const query = `
      SELECT 
        id,
        timestamp,
        ip_origem,
        hora_dia,
        nivel_risco,
        acao_executada
      FROM logs_auditoria
      WHERE usuario_id = ?
      ORDER BY timestamp DESC
      LIMIT ?
    `;

    db.all(query, [usuarioId, limit], (err, rows) => {
      if (err) {
        reject(err);
      } else {
        resolve(rows);
      }
    });
  });
}

module.exports = {
  findUserByEmail,
  createUser,
  incrementFailedAttempts,
  lockUserAccount,
  resetUserLock,
  createAuditLog,
  getUserLoginHistory,
};
