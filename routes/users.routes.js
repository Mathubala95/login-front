var express = require('express');
const { userRegister, allUsers, userLogin, forgotPassword, resetPassword } = require('../controller/users.controller');
var router = express.Router();

/* User Route. */
router.post('/register', userRegister);

router.get("/", allUsers);

router.post("/login", userLogin);

router.post("/forgotpassword", forgotPassword);

router.post("/resetpassword", resetPassword);

module.exports = router;
