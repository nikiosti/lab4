require("dotenv").config();
const request = require("supertest");
const { app, server } = require("./app.js");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

describe("Auth API", () => {
  beforeAll(async () => {
    await prisma.user.deleteMany({
      where: {
        username: "testuser",
      },
    });
  });

  afterAll(async () => {
    await prisma.$disconnect();
    server.close();
  });

  test("POST /register - should register a new user", async () => {
    const response = await request(app)
      .post("/register")
      .send({ username: "testuser", password: "password123" });

    expect(response.status).toBe(200);
    expect(response.body).toHaveProperty("accessToken");
    expect(response.body).toHaveProperty("refreshToken");
  });
});
