const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "chave_secreta_gatekeeper_ai";
const AI_SERVICE_URL =
  process.env.AI_SERVICE_URL || "http://localhost:5000/predict";

app.use(express.json());
app.use(cors());
app.use(express.static("public"));

// ==========================================
// CONEXÃO E CRIAÇÃO AUTOMÁTICA DAS TABELAS (SQLite)
// ==========================================
const dbPath = path.resolve(__dirname, "gatekeeper.db");
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Erro ao conectar ao banco:", err.message);
  } else {
    console.log("[SQLite] Conectado ao banco de dados com sucesso.");
  }
});

// Inicialização automática das tabelas se não existirem
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      senha_hash TEXT NOT NULL,
      tentativas_falhas INTEGER DEFAULT 0,
      bloqueado_ate TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS logs_auditoria (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER,
      timestamp TEXT DEFAULT (DATETIME('now')),
      ip_origem TEXT,
      hora_dia INTEGER,
      nivel_risco TEXT,
      acao_executada TEXT,
      FOREIGN KEY (usuario_id) REFERENCES usuarios (id) ON DELETE SET NULL
    )
  `);
});

// Helper para IP do cliente
function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"] || req.socket.remoteAddress || "127.0.0.1"
  );
}

// RN-01: Validação de Senha Forte
function validatePassword(password) {
  if (!password || password.length < 8) {
    return {
      valid: false,
      message: "A senha deve conter no mínimo 8 caracteres.",
    };
  }
  const hasUpperCase = /[A-Z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[@#$%^&*!_+\-=\[\]{};':"\\|,.<>\/?]/.test(password);

  if (!hasUpperCase)
    return {
      valid: false,
      message: "A senha deve conter pelo menos uma letra maiúscula.",
    };
  if (!hasNumber)
    return {
      valid: false,
      message: "A senha deve conter pelo menos um número.",
    };
  if (!hasSpecialChar)
    return {
      valid: false,
      message: "A senha deve conter pelo menos um caractere especial.",
    };

  return { valid: true };
}

// Operações de Banco
const dbOps = {
  findUserByEmail: (email) => {
    return new Promise((resolve, reject) => {
      db.get(`SELECT * FROM usuarios WHERE email = ?`, [email], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });
  },
  createUser: (email, senhaHash) => {
    return new Promise((resolve, reject) => {
      db.run(
        `INSERT INTO usuarios (email, senha_hash, tentativas_falhas) VALUES (?, ?, 0)`,
        [email, senhaHash],
        function (err) {
          if (err) reject(err);
          else resolve(this.lastID);
        },
      );
    });
  },
  incrementFailedAttempts: (userId, attempts) => {
    return new Promise((resolve, reject) => {
      db.run(
        `UPDATE usuarios SET tentativas_falhas = ? WHERE id = ?`,
        [attempts, userId],
        (err) => {
          if (err) reject(err);
          else resolve();
        },
      );
    });
  },
  lockUserAccount: (userId, blockedUntil) => {
    return new Promise((resolve, reject) => {
      db.run(
        `UPDATE usuarios SET tentativas_falhas = 3, bloqueado_ate = ? WHERE id = ?`,
        [blockedUntil, userId],
        (err) => {
          if (err) reject(err);
          else resolve();
        },
      );
    });
  },
  resetUserLock: (userId) => {
    return new Promise((resolve, reject) => {
      db.run(
        `UPDATE usuarios SET tentativas_falhas = 0, bloqueado_ate = NULL WHERE id = ?`,
        [userId],
        (err) => {
          if (err) reject(err);
          else resolve();
        },
      );
    });
  },
  createAuditLog: ({ ipOrigem, horaDia, nivelRisco, acaoExecutada }) => {
    return new Promise((resolve, reject) => {
      const query = `
        INSERT INTO logs_auditoria (timestamp, ip_origem, hora_dia, nivel_risco, acao_executada)
        VALUES (DATETIME('now'), ?, ?, ?, ?)
      `;
      db.run(
        query,
        [ipOrigem, horaDia, nivelRisco, acaoExecutada],
        function (err) {
          if (err) reject(err);
          else resolve(this.lastID);
        },
      );
    });
  },
};

// ==========================================
// ROTAS DE AUTENTICAÇÃO
// ==========================================

app.post("/api/auth/register", async (req, res) => {
  const { email, password } = req.body;
  const ipOrigem = getClientIP(req);
  const horaDia = new Date().getHours();

  if (!email || !password) {
    return res.status(400).json({ error: "E-mail e senha são obrigatórios." });
  }

  const passwordValidation = validatePassword(password);
  if (!passwordValidation.valid) {
    return res.status(400).json({ error: passwordValidation.message });
  }

  try {
    const existingUser = await dbOps.findUserByEmail(email);
    if (existingUser) {
      return res.status(409).json({ error: "Este e-mail já está cadastrado." });
    }

    const senhaHash = await bcrypt.hash(password, 10);
    const userId = await dbOps.createUser(email, senhaHash);

    await dbOps.createAuditLog({
      ipOrigem,
      horaDia,
      nivelRisco: "Baixo",
      acaoExecutada: "CADASTRO_SUCESSO",
    });

    return res
      .status(201)
      .json({ message: "Usuário cadastrado com sucesso.", userId });
  } catch (error) {
    console.error("Erro detalhado no cadastro:", error);
    return res
      .status(500)
      .json({ error: "Erro interno ao realizar cadastro." });
  }
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password, codigoPais = 1 } = req.body;
  const ipOrigem = getClientIP(req);
  const horaDia = new Date().getHours();

  if (!email || !password) {
    return res.status(400).json({ error: "E-mail e senha são obrigatórios." });
  }

  try {
    const user = await dbOps.findUserByEmail(email);

    if (!user) {
      await dbOps.createAuditLog({
        ipOrigem,
        horaDia,
        nivelRisco: "Alto",
        acaoExecutada: "LOGIN_FALHA_EMAIL_INEXISTENTE",
      });
      return res.status(401).json({ error: "Credenciais inválidas." });
    }

    if (user.bloqueado_ate) {
      const now = new Date();
      const blockedUntil = new Date(user.bloqueado_ate);

      if (now < blockedUntil) {
        const remainingMinutes = Math.ceil((blockedUntil - now) / (1000 * 60));
        await dbOps.createAuditLog({
          ipOrigem,
          horaDia,
          nivelRisco: "Alto",
          acaoExecutada: "CONTA_BLOQUEADA",
        });
        return res.status(423).json({
          error: `Conta bloqueada por múltiplas falhas. Tente novamente em ${remainingMinutes} minuto(s).`,
        });
      } else {
        await dbOps.resetUserLock(user.id);
        user.tentativas_falhas = 0;
      }
    }

    const isPasswordValid = await bcrypt.compare(password, user.senha_hash);

    if (!isPasswordValid) {
      const newFailedAttempts = (user.tentativas_falhas || 0) + 1;

      if (newFailedAttempts >= 3) {
        const blockUntil = new Date(Date.now() + 15 * 60 * 1000).toISOString();
        await dbOps.lockUserAccount(user.id, blockUntil);

        await dbOps.createAuditLog({
          ipOrigem,
          horaDia,
          nivelRisco: "Alto",
          acaoExecutada: "CONTA_BLOQUEADA",
        });

        return res.status(423).json({
          error:
            "Múltiplas tentativas incorretas. Sua conta foi bloqueada temporariamente por 15 minutos.",
        });
      } else {
        await dbOps.incrementFailedAttempts(user.id, newFailedAttempts);

        await dbOps.createAuditLog({
          ipOrigem,
          horaDia,
          nivelRisco: "Baixo",
          acaoExecutada: "SENHA_INCORRETA",
        });

        return res.status(401).json({
          error: `Credenciais inválidas. Você tem mais ${3 - newFailedAttempts} tentativa(s) antes do bloqueio.`,
        });
      }
    }

    await dbOps.resetUserLock(user.id);

    let nivelRisco = "Baixo";
    try {
      const aiResponse = await axios.post(
        AI_SERVICE_URL,
        {
          hora_dia: horaDia,
          codigo_pais: codigoPais,
        },
        { timeout: 3000 },
      );

      nivelRisco = aiResponse.data.risk_level || "Baixo";
    } catch (aiError) {
      console.warn(
        "Aviso: Microsserviço de IA indisponível. Aplicando risco Baixo (Fallback).",
      );
    }

    if (nivelRisco === "Alto") {
      await dbOps.createAuditLog({
        ipOrigem,
        horaDia,
        nivelRisco: "Alto",
        acaoExecutada: "2FA_SOLICITADO",
      });

      return res.status(202).json({
        status: "PENDING_2FA",
        message: "Acesso retido por padrão anômalo. Validação 2FA necessária.",
        userId: user.id,
      });
    }

    const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "30m",
    });

    await dbOps.createAuditLog({
      ipOrigem,
      horaDia,
      nivelRisco: "Baixo",
      acaoExecutada: "LOGIN_CONCEDIDO",
    });

    return res.status(200).json({
      message: "Login realizado com sucesso.",
      token,
      expiresIn: "30m",
    });
  } catch (error) {
    console.error("Erro no login:", error);
    return res
      .status(500)
      .json({ error: "Erro interno durante a autenticação." });
  }
});

app.listen(PORT, () => {
  console.log(`[GateKeeper AI] Servidor backend rodando na porta ${PORT}`);
});
