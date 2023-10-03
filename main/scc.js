const { sign, verify } = require("jsonwebtoken");

// Função para criar tokens
const criarToken = (usuario) => {
  const tokenAcesso = sign({ nome: usuario.nome, id: usuario.id }, "jwtsecret");
  return tokenAcesso;
};

// Middleware para validar o token
const validarToken = (req, res, next) => {
  const tokenAcesso = req.cookies["token-acesso"];

  if (!tokenAcesso) {
    return res.status(401).json("Token não fornecido");
  }

  try {
    const tokenDecodificado = verify(tokenAcesso, "jwtsecret");

    if (tokenDecodificado) {
      req.autenticado = true;
      return next();
    }
  } catch (error) {
    return res.status(403).json("Token inválido");
  }
};

module.exports = { criarToken, validarToken };

module.exports = { criarToken, validarToken };
