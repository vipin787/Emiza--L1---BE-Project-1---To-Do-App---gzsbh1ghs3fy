const User = require("../models/user.js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const saltRounds = 10;
const JWT_SECRET = "newtonSchool";

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "User with this E-mail does not exist !!",
        status: "fail",
      });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(403).json({
        message: "Invalid Password, try again !!",
        status: "fail",
      });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.status(200).json({
      status: "success",
      token: token,
    });
  } catch (error) {
    return res.status(404).json({
      message: "Something went wrong",
      status: "fail",
    });
  }
};

const signupUser = async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        status: "fail",
        message: "User with given Email already registered",
      });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      role,
    });

    await newUser.save();

    return res.status(200).json({
      status: "success",
      message: "User SignedUp successfully",
    });
  } catch (error) {
    return res.status(404).json({
      status: "fail",
      message: "Something went wrong",
    });
  }
};

module.exports = { loginUser, signupUser };
