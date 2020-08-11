const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
const config = require("config");

const User = require("../modals/User");

// @route       POST api/users
// @desc        Register a user
// @access      Public
router.post(
  "/",
  [
    // Name should not be empty
    body("name", "Please enter a name").not().isEmpty(),
    body("email", "Please include a valid email").isEmail(),
    body(
      "password",
      "Please enter a password with 6 or more character"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    // Find the validation error in this request and wraps them in an object
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password } = req.body;
    try {
      let user = await User.findOne({ email });
      // If user already exist
      if (user) {
        return res.status(400).json({ msg: "User already exists" });
      }
      // Create user and save into the database
      user = new User({
        name,
        email,
        password,
      });
      // Encrypt password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(password, salt);
      await user.save();

      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get("jwtSecret"),
        {
          expiresIn: 360000,
        },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server Error");
    }
  }
);

module.exports = router;
