const express = require("express");
const { PrismaClient } = require("@prisma/client");
const cookiePaser = require("cookie-parser");
const bycrpt = require("bcrypt");
const { createTokens, validateToken } = require("./JWT");

const app = express();

app.use(express.json());
app.use(cookiePaser());

const prisma = new PrismaClient();

app.post("/registra", async (req, res) => {
  const { nome, email, senha } = req.body;
  await bycrpt
    .hash(senha, 10)
    .then((hash) => {
      prisma.usuario.create({
        nome,
        email,
        senha: hash,
      });
    })
    .then(() => {
      res.json("Usuario criado");
    })
    .catch(() => {
      res.json({ err: "Algo deu errado!!!" });
    });
});

app.post("/login", async (req, res) => {
  const { nome, senha } = req.body;
  const usuario = await prisma.usuario.findFirst({
    where: { nome, email },
  });
  if (!usuario) {
    res.status(404).json({ erro: "usuario não existe!!!" });
  }
  const pSenha = usuario.senha;
  bycrpt.compare(senha, pSenha).then((match) => {
    if (!match) {
      res.json({ error: "senha Incorreta!!!" });
    } else {
      const acessToken = createTokens(usuario);
      res.cookie("acess-token", acessToken, {
        httpOnly: false,
      });
      res.json("Logged In");
    }
  });
});

app.get("/perfil", validateToken, (req, res) => {
  res.json("Entrou no perfil!!!");
});

app.listen(8080, () => {
  console.log("Running on port 8080");
});
