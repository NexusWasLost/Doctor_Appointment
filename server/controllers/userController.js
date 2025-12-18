const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Doctor = require("../models/doctorModel");
const Appointment = require("../models/appointmentModel");
const nodemailer = require("nodemailer");
const { testMail, testPass } = require("../utils/checkCred.js");
require("dotenv").config();

const getuser = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    return res.send(user);
  } catch (error) {
    res.status(500).send("Unable to get user");
  }
};

const getallusers = async (req, res) => {
  try {
    const users = await User.find()
      .find({ _id: { $ne: req.locals } })
      .select("-password");
    return res.send(users);
  } catch (error) {
    res.status(500).send("Unable to get all users");
  }
};

const login = async (req, res) => {
  try {
    const emailPresent = await User.findOne({ email: req.body.email });
    if (!emailPresent) {
      return res.status(400).send("Incorrect credentials");
    }
    if(emailPresent.role != req.body.role){
      return res.status(404).send("Role does not exist");
    }
    const verifyPass = await bcrypt.compare(
      req.body.password,
      emailPresent.password
    );
    if (!verifyPass) {
      return res.status(400).send("Incorrect credentials");
    }

    const token = jwt.sign(
      { userId: emailPresent._id, isAdmin: emailPresent.isAdmin, role:emailPresent.role },
      process.env.JWT_SECRET,
      {
        expiresIn: "2 days",
      }
    );
    return res.status(201).send({ msg: "User logged in successfully", token });
  } catch (error) {
    console.log(error);
    res.status(500).send("Unable to login user");
  }
};

const register = async (req, res) => {
  try {
    //check if email and password are sent as part of the request body
    if(!req.body.email || !req.body.password){
      return res.status(400).send("Must contain all the credentials");
    }

    //check if mail is valid or not
    if(!testMail(req.body.email)){
      return res.status(400).send("Email must be a valid mail");
    }

    //check if password is valid or not
    if(!testPass(req.body.password)){
      return res.status(400).send("Password must be atleast 8 characters containing atleast 1 letter, 1 digit and 1 symbol");
    }

    const emailPresent = await User.findOne({ email: req.body.email });
    if (emailPresent) {
      return res.status(400).send("Email already exists");
    }

    const hashedPass = await bcrypt.hash(req.body.password, 10);
    const user = await User({ ...req.body, password: hashedPass });
    const result = await user.save();
    if (!result) {
      return res.status(500).send("Unable to register user");
    }
    return res.status(201).send("User registered successfully");
  } catch (error) {
    res.status(500).send("Unable to register user");
  }
};

const updateprofile = async (req, res) => {
  try {
    const hashedPass = await bcrypt.hash(req.body.password, 10);
    const result = await User.findByIdAndUpdate(
      { _id: req.locals },
      { ...req.body, password: hashedPass }
    );
    if (!result) {
      return res.status(500).send("Unable to update user");
    }
    return res.status(201).send("User updated successfully");
  } catch (error) {
    res.status(500).send("Unable to update user");
  }
};
const changepassword = async (req, res) => {
  try {
    console.log(req.body);
    const { userId, currentPassword, newPassword, confirmNewPassword } = req.body;
    // console.log("Received newPassword:", newPassword);
    if (newPassword !== confirmNewPassword) {
      return res.status(400).send("Passwords do not match");
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).send("User not found");
    }

    const isPasswordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordMatch) {
      return res.status(400).send("Incorrect current password");
    }

    const saltRounds = 10;
    // console.log("Using saltRounds:", saltRounds);

    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);
    // console.log("Hashed new password:", hashedNewPassword);

    user.password = hashedNewPassword;
    await user.save();

    return res.status(200).send("Password changed successfully");
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal Server Error");
  }
};

const deleteuser = async (req, res) => {
  try {
    const result = await User.findByIdAndDelete(req.body.userId);
    const removeDoc = await Doctor.findOneAndDelete({
      userId: req.body.userId,
    });
    const removeAppoint = await Appointment.findOneAndDelete({
      userId: req.body.userId,
    });
    return res.send("User deleted successfully");
  } catch (error) {
    res.status(500).send("Unable to delete user");
  }
};

const resetpassword = async (req, res) => {
  try {
    const { id, token } = req.params;
    const { password } = req.body;
    // console.log(token)
    // console.log(password);
    jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
      if (err) {
        console.log(err);
        return res.status(400).send({ error: "Invalid or expired token" });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.findByIdAndUpdate(id, { password: hashedPassword });
        return res.status(200).send({ success: "Password reset successfully" });
      } catch (updateError) {
        console.error("Error updating password:", updateError);
        return res.status(500).send({ error: "Failed to update password" });
      }
    });
  } catch (error) {
    console.error(error);
    return res.status(500).send({ error: "Internal Server Error" });
  }
};


module.exports = {
  getuser,
  getallusers,
  login,
  register,
  updateprofile,
  deleteuser,
  changepassword,
  resetpassword,
};
