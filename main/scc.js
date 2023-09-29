const { sign, verify } = require("jsonwebtoken");

const createTokens = (usuario) => {
  const acessToken = sing({ nome: usuario.nome, id: usuario.id }, "jwtsecret");

  return acessToken;
};

const validateToken = (req, res, next) => {
  const acessToken = req.cookies["acess-token"];
  if (!acessToken) return res.status(404).json("Algo deu errado");

  try {
    const validToken = verify(acessToken, "jwtsecret");
    if (validToken) {
      req.athenticated = true;
      return next();
    }
  } catch (error) {}
};

module.exports = { createTokens, validateToken };
