const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongodb = require("mongodb");
const crypto = require("crypto");
const { connectDb, closeConnection } = require("../db/connection");
// const { passwordResetEmail } = require("../lib/sendEmail");

/*User Registration*/
let userRegister = async (req, res) => {
  try {
    const db = await connectDb();
    const userEmail = await db
      .collection("users")
      .findOne({ email: req.body.email });

    if (!userEmail) {
      req.body.createdAt = new Date().toString();
      req.body.role = "USER";

      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(req.body.password, salt);
      req.body.password = hash;
      delete req.body.confirmpassword;

      const userData = await db.collection("users").insertOne(req.body);
      res.json({ message: "User Added Successfully !" });

      await closeConnection();
    } else {
      res.status(401).json({ message: "This Email Id already Exists !" });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error !" });
  }
};

/*All User*/
let allUsers = async (req, res) => {
  try {
    let db = await connectDb();
    let userData = await db.collection("users").find().toArray();
    if (!userData || userData.length == 0) {
      res.status(404).json({ message: "No User Data Found !" });
    } else {
      res.json(userData);
    }

    await closeConnection();
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error !" });
  }
};

/*User Login*/
let userLogin = async (req, res) => {
  try {
    const db = await connectDb();
    const userEmail = await db
      .collection("users")
      .findOne({ email: req.body.email });

    if (userEmail) {
      const compare = await bcrypt.compare(
        req.body.password,
        userEmail.password
      );
      if (compare) {
        const token = jwt.sign({ _id: userEmail._id }, process.env.JWT_SECRET, {
          expiresIn: "24h",
        });
        res.json({
          token: token,
          role: userEmail.role,
          uId: userEmail._id,
          uNm: userEmail.userName,
        });
      } else {
        res.status(401).json({ message: "Invalid Email/Password" });
      }
    } else {
      res.status(401).json({ message: "Invalid Email/Password" });
    }
    await closeConnection();
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error !" });
  }
};

/*User Forgot Password*/
let forgotPassword = async (req, res) => {
  try {
    const db = await connectDb();
    const userEmail = await db
      .collection("users")
      .findOne({ email: req.body.email });

    if (userEmail) {
      const token = await db
        .collection("token")
        .findOne({ userId: userEmail._id });

      if (token) {
        await db.collection("token").deleteOne({ userId: userEmail._id });
      }

      let newToken = crypto.randomBytes(32).toString("hex");
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(newToken, salt);
      const tokenPayload = await db.collection("token").insertOne({
        userId: new mongodb.ObjectId(userEmail._id),
        token: hash,
        expirationTime: Date.now() + 300 * 1000,
      });

      const link = `${process.env.PASSWORD_RESET}/passwordReset?token=${newToken}&id=${userEmail._id}`;
      let subject = `Dear ${userEmail.userName},`;

      await passwordResetEmail(
        userEmail.email,
        "Password Reset Link",
        subject,
        link
      );

      return res.status(200).json({
        message: "Password Reset link has been send to your registered email, Please make use of this link within 5 mins.",
      });
    } else {
      res.status(404).json({ message: "User Email Id does not Exist !" });
    }
    await closeConnection();
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error !" });
  }
};

/*User Reset Password*/
let resetPassword = async (req, res) => {
  try {
    const db = await connectDb();
    let resetToken = await db
      .collection("token")
      .findOne({ userId: new mongodb.ObjectId(req.body.userId) });

    if (resetToken) {
      if (resetToken.expirationTime > Date.now()) {
        const isValid = await bcrypt.compare(req.body.token, resetToken.token);

        if (isValid) {
          const salt = await bcrypt.genSalt(10);
          const hash = await bcrypt.hash(req.body.password, salt);
          req.body.password = hash;
          delete req.body.confirmpassword;

          let newPassword = await db
            .collection("users")
            .updateOne(
              { _id: resetToken.userId },
              { $set: { password: req.body.password } }
            );

          res.json({ message: "Password has been changed successfully.." });

          await db
            .collection("token")
            .deleteOne({ userId: resetToken.userId });
        } else {
          res.status(401).json({ message: "Invalid Token, Please try again with new link.." });
        }
      } else {
        res.status(400).json({
          message: "Token Expired, Please try again with new link..",
        });
      }
    } else {
      return res.status(401).json({
        message: "No token, Please try again with new link..",
      });
    }
    await closeConnection();
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error !" });
  }
};

module.exports = {
  userRegister,
  allUsers,
  userLogin,
  forgotPassword,
  resetPassword,
};