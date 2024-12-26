require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

const generateAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRATION,
  });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRATION,
  });
};

// Middleware для проверки access-токена
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Middleware для проверки прав доступа (например, доступ только к admin)
const authorizeAdmin = async (req, res, next) => {
  const token = jwt.verify(
    req.headers["authorization"],
    process.env.JWT_SECRET
  );

  const user = await prisma.user.findUnique({
    where: {
      id: token.userId,
    },
  });

  if (user.role !== "admin") return res.sendStatus(403);
  next();
};

// Регистрация
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: { username, password: hashedPassword },
    });

    const accessToken = generateAccessToken(user.id);
    const refreshToken = generateRefreshToken(user.id);

    res.status(200).json({ accessToken, refreshToken });
  } catch (error) {
    res.status(400).json({ error: "Username already exists" });
  }
});

// Вход
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await prisma.user.findUnique({ where: { username } });

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const accessToken = generateAccessToken(user.id);
  const refreshToken = generateRefreshToken(user.id);

  res.json({ accessToken, refreshToken });
});

app.post("/refresh-token", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.sendStatus(401);

  const user = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
  const newAccessToken = generateAccessToken(user.userId);
  const newRefreshToken = generateRefreshToken(user.userId);

  res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
});

// Пример защищённого маршрута
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "This is a protected route", userId: req.user.userId });
});

// Пример маршрута, доступного только для админов
app.get("/admin", authenticateToken, authorizeAdmin, (req, res) => {
  res.json({ message: "This is an admin route" });
});

app.post("/logout", authenticateToken, async (req, res) => {
  await prisma.user.update({
    where: { id: req.user.userId },
    data: { refreshToken: null },
  });
  res.json({ message: "Logged out successfully" });
});

const server = app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});

// Экспортируем сервер для тестирования
module.exports = { app, server };
