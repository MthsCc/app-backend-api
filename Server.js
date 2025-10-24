// ==========================
// SERVER.JS PRONTO PARA RENDER
// ==========================

import dotenv from "dotenv";
dotenv.config(); // ⚠️ dotenv deve vir antes de qualquer uso de process.env

import express from "express";
import cors from "cors";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import nodemailer from "nodemailer";
import crypto from "crypto";

// --------------------------
// CONFIGURAÇÕES INICIAIS
// --------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const prisma = new PrismaClient();
const SECRET_KEY = process.env.SECRET_KEY || "sua_chave_secreta";

// --------------------------
// MIDDLEWARES
// --------------------------
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// --------------------------
// EMAIL CONFIG
// --------------------------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'seu_email@gmail.com',
    pass: process.env.EMAIL_PASSWORD || 'sua_senha_de_app',
  }
});

function generateResetCode() {
  return crypto.randomBytes(3).toString('hex').toUpperCase();
}

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({ from: process.env.EMAIL_USER, to, subject, html });
    return true;
  } catch (error) {
    console.error('Erro ao enviar email:', error);
    return false;
  }
}

// --------------------------
// ROTAS DE AUTENTICAÇÃO
// --------------------------
app.post("/register", async (req, res) => {
  try {
    const { name, email, password, isAdmin } = req.body;
    if (!password) return res.status(400).json({ error: "Senha é obrigatória" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const novoUsuario = await prisma.user.create({
      data: { name, email, password: hashedPassword, isAdmin: !!isAdmin },
    });

    res.status(201).json({ message: "Usuário registrado com sucesso", userId: novoUsuario.id });
  } catch (error) {
    console.error(error);
    if (error.code === "P2002") return res.status(400).json({ error: "E-mail já cadastrado" });
    res.status(500).json({ error: "Erro ao registrar usuário" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) return res.status(400).json({ error: "Usuário ou senha incorretos" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Usuário ou senha incorretos" });

    const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao fazer login" });
  }
});

// --------------------------
// RECUPERAÇÃO DE SENHA
// --------------------------
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "E-mail não encontrado" });

    const resetCode = generateResetCode();
    const resetCodeHash = await bcrypt.hash(resetCode, 10);
    const resetCodeExpires = new Date(Date.now() + 15 * 60 * 1000);

    await prisma.user.update({
      where: { id: user.id },
      data: { resetCode: resetCodeHash, resetCodeExpires }
    });

    const emailHtml = `
      <h2>Recuperação de Senha</h2>
      <p>Seu código de recuperação é: <strong>${resetCode}</strong></p>
      <p>Este código expira em 15 minutos.</p>
    `;

    if (!(await sendEmail(email, 'Código de Recuperação de Senha', emailHtml))) {
      return res.status(500).json({ error: "Erro ao enviar e-mail" });
    }

    res.json({ message: "Código de recuperação enviado para seu e-mail" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao processar recuperação de senha" });
  }
});

app.post("/reset-password", async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!code || !newPassword) return res.status(400).json({ error: "Código e nova senha são obrigatórios" });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "Usuário não encontrado" });

    if (!user.resetCode || !user.resetCodeExpires || new Date() > user.resetCodeExpires)
      return res.status(400).json({ error: "Código inválido ou expirado" });

    const codeValid = await bcrypt.compare(code, user.resetCode);
    if (!codeValid) return res.status(400).json({ error: "Código incorreto" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword, resetCode: null, resetCodeExpires: null }
    });

    res.json({ message: "Senha alterada com sucesso" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao resetar senha" });
  }
});

// --------------------------
// MIDDLEWARES DE AUTORIZAÇÃO
// --------------------------
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token não fornecido" });
  const token = authHeader.split(" ")[1];
  try {
    req.user = jwt.verify(token, SECRET_KEY);
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
};

const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: "Acesso negado" });
  next();
};

// --------------------------
// ROTAS DE USUÁRIO
// --------------------------
app.get("/usuarios/me", authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
    const { password, resetCode, resetCodeExpires, ...rest } = user;
    res.json(rest);
  } catch (err) { console.error(err); res.status(500).json({ error: "Erro" }); }
});

app.get("/usuarios/todos", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    const usersWithoutSensitive = users.map(({ password, resetCode, resetCodeExpires, ...rest }) => rest);
    res.json(usersWithoutSensitive);
  } catch (err) { console.error(err); res.status(500).json({ error: "Erro" }); }
});

// --------------------------
// INICIAR SERVIDOR
// --------------------------
const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor rodando em http://0.0.0.0:${PORT}`);
});

// Evita timeouts intermitentes
server.keepAliveTimeout = 120000; // 120 segundos
server.headersTimeout = 120000;
