const jwt = require("jsonwebtoken");

// User Based Authentication
function authenticate(req, res, next) {
  try {
    if (req.headers.authorization) {
      jwt.verify(
        req.headers.authorization,
        process.env.JWT_SECRET,
        (err, decoded) => {
          if (decoded == undefined) {
            res.status(401).json({ message: "Unauthorized" });
          } else {
            req.userId = decoded._id;
            req.role = decoded.role;
            next();
          }
        }
      );
    } else {
      res.status(401).json({ message: "Unauthorized, Token not found" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Something went wrong" });
  }
}

module.exports = { authenticate };