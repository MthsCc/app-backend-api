import express from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import dotenv from "dotenv";
import cors from 'cors';
import nodemailer from 'nodemailer';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const prisma = new PrismaClient();
const SECRET_KEY = process.env.SECRET_KEY || "sua_chave_secreta";

// ✅ CORS DEVE ESTAR AQUI (ANTES DAS ROTAS)
app.use(cors());

// Middleware para parsear JSON
app.use(express.json());

// Servir arquivos estáticos (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));

// =============== CONFIGURAÇÃO DE EMAIL ===============
// Use variáveis de ambiente para suas credenciais
const transporter = nodemailer.createTransport({
  service: 'gmail', // ou outro serviço de email
  auth: {
    user: process.env.EMAIL_USER || 'seu_email@gmail.com',
    pass: process.env.EMAIL_PASSWORD || 'sua_senha_de_app', // Use App Password do Gmail
  }
});

// Função para gerar código de recuperação
function generateResetCode() {
  return crypto.randomBytes(3).toString('hex').toUpperCase(); // 6 caracteres
}

// Função para enviar email
async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER || 'seu_email@gmail.com',
      to,
      subject,
      html
    });
    return true;
  } catch (error) {
    console.error('Erro ao enviar email:', error);
    return false;
  }
}

// =============== AUTENTICAÇÃO ===============
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

// =============== RECUPERAÇÃO DE SENHA ===============
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "E-mail não encontrado" });

    // Gerar código de recuperação
    const resetCode = generateResetCode();
    const resetCodeHash = await bcrypt.hash(resetCode, 10);
    const resetCodeExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutos

    // Salvar código no banco de dados
    await prisma.user.update({
      where: { id: user.id },
      data: {
        resetCode: resetCodeHash,
        resetCodeExpires
      }
    });

    // Enviar email
    const emailHtml = `
      <h2>Recuperação de Senha</h2>
      <p>Seu código de recuperação é: <strong>${resetCode}</strong></p>
      <p>Este código expira em 15 minutos.</p>
      <p>Se você não solicitou isso, ignore este e-mail.</p>
    `;

    const emailSent = await sendEmail(email, 'Código de Recuperação de Senha', emailHtml);

    if (!emailSent) {
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

    if (!code || !newPassword) {
      return res.status(400).json({ error: "Código e nova senha são obrigatórios" });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "Usuário não encontrado" });

    // Verificar se o código existe e não expirou
    if (!user.resetCode || !user.resetCodeExpires) {
      return res.status(400).json({ error: "Código de recuperação inválido ou expirado" });
    }

    if (new Date() > user.resetCodeExpires) {
      return res.status(400).json({ error: "Código de recuperação expirado" });
    }

    // Verificar se o código está correto
    const codeValid = await bcrypt.compare(code, user.resetCode);
    if (!codeValid) {
      return res.status(400).json({ error: "Código de recuperação incorreto" });
    }

    // Atualizar senha
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashedPassword,
        resetCode: null,
        resetCodeExpires: null
      }
    });

    res.json({ message: "Senha alterada com sucesso" });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Erro ao resetar senha" });
  }
});

// =============== MIDDLEWARE ===============
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Token não fornecido" });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
};

const adminMiddleware = (req, res, next) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: "Acesso negado" });
  next();
};

// =============== ROTAS ===============

// Listar próprio usuário
app.get("/usuarios/me", authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    if (!user) return res.status(404).json({ error: "Usuário não encontrado" });
    const { password, resetCode, resetCodeExpires, ...rest } = user;
    res.json(rest);
  } catch (err) { console.error(err); res.status(500).json({ error: "Erro" }); }
});

// Usuário logado (apenas name/email)
app.get("/usuarios", authMiddleware, async (req, res) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    res.json({ name: user.name, email: user.email });
  } catch (err) { console.error(err); res.status(500).json({ error: "Erro" }); }
});

// Admin vê todos
app.get("/usuarios/todos", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    const usersWithoutPassword = users.map(({ password, resetCode, resetCodeExpires, ...rest }) => rest);
    res.json(usersWithoutPassword);
  } catch (err) { console.error(err); res.status(500).json({ error: "Erro" }); }
});

// Atualizar usuário
app.put("/usuarios/:id", authMiddleware, async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const data = {};
    if (name) data.name = name;
    if (email) data.email = email;
    if (password) data.password = await bcrypt.hash(password, 10);

    const updated = await prisma.user.update({ where: { id: req.params.id }, data });
    const { password: _, resetCode, resetCodeExpires, ...rest } = updated;
    res.json(rest);
  } catch (err) { console.error(err); res.status(404).json({ error: "Usuário não encontrado" }); }
});

// Deletar usuário
app.delete("/usuarios/:id", authMiddleware, async (req, res) => {
  try {
    await prisma.user.delete({ where: { id: req.params.id } });
    res.json({ message: "Usuário deletado com sucesso" });
  } catch (err) { console.error(err); res.status(404).json({ error: "Usuário não encontrado" }); }
});

// =============== INICIAR ===============
dotenv.config();
app.listen(3000, () => console.log("Servidor rodando na porta 3000"));
/*
NHQc48tMTc8PQFsH
*/ 
