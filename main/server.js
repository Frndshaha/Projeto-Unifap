const express = require("express");
const { PrismaClient } = require("@prisma/client");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const { criarToken, validarToken } = require("./JWT");

const app = express();

app.use(express.json());
app.use(cookieParser());

const prisma = new PrismaClient();

app.post("/registrar", async (req, res) => {
  const { nome, email, senha } = req.body;

  try {
    const hash = await bcrypt.hash(senha, 10);
    await prisma.usuario.create({
      nome,
      email,
      senha: hash,
    });
    res.json("Usuário criado");
  } catch (error) {
    res.status(500).json({ erro: "Algo deu errado" });
  }
});

app.post("/login", async (req, res) => {
  const { nome, senha } = req.body;

  try {
    const usuario = await prisma.usuario.findFirst({
      where: { nome },
    });

    if (!usuario) {
      res.status(404).json({ erro: "Usuário não encontrado" });
    }

    const senhaHash = usuario.senha;
    const match = await bcrypt.compare(senha, senhaHash);

    if (!match) {
      res.json({ erro: "Senha incorreta" });
    } else {
      const accessToken = criarToken(usuario);
      res.cookie("access-token", accessToken, {
        httpOnly: false,
      });
      res.json("Logado com sucesso");
    }
  } catch (error) {
    res.status(500).json({ erro: "Algo deu errado" });
  }
});

app.get("/perfil", validarToken, (req, res) => {
  res.json("Você entrou no perfil");
});

app.listen(8080, () => {
  console.log("Rodando na porta 8080");
});
