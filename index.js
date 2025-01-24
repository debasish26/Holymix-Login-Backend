const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI);

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => console.log('Connected to MongoDB'));

// JWT Secret Key
const SECRET_KEY = process.env.SECRET_KEY; // Replace with a secure, random string

// Generate OTP
function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}

// Email transport
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS, // Replace with an app password (not your actual password)
  },
});

// User schema
const userSchema = new mongoose.Schema({
  firstName: String,
  lastName: String,
  email: { type: String, unique: true, required: true },
  password: String,
  otp: String,
  otpExpires: Date,
  isVerified: { type: Boolean, default: false },
});

const User = mongoose.model('User', userSchema);

// Register route
app.post('/register', async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      if (existingUser.isVerified) {
        return res.status(400).json({ error: 'Email already exists' });
      } else {
        return res
          .status(400)
          .json({ error: 'Account already registered but not verified. Check your email for OTP.' });
      }
    }

    const otp = generateOTP();
    const otpExpires = new Date(Date.now() + 30 * 1000); // OTP expires in 30 seconds

    const newUser = new User({ firstName, lastName, email, password, otp, otpExpires, isVerified: false });
    await newUser.save();

    await transporter.sendMail({
      from: 'AnimeStream <your-email@gmail.com>',
      to: email,
      subject: 'Verify Your Email',
      text: `Your OTP is: ${otp}`,
    });

    setTimeout(async () => {
      try {
        const user = await User.findOne({ email });

        if (user && !user.isVerified) {
          console.log(`Deleting unverified user with email: ${email}`);
          await User.deleteOne({ email });
        }
      } catch (err) {
        console.error('Error while deleting unverified user:', err);
      }
    }, 60 * 1000); // Delete unverified users after 60 seconds

    res.status(201).json({ message: 'User registered, check email for OTP' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

// Verify OTP route
app.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: 'Email already verified' });
    }

    if (user.otp !== otp || user.otpExpires < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }

    user.otp = null;
    user.otpExpires = null;
    user.isVerified = true;
    await user.save();

    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
      const user = await User.findOne({ email });

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      if (!user.isVerified) {
        return res.status(400).json({ error: 'Email not verified. Check your email for OTP.' });
      }

      if (user.password !== password) {
        return res.status(400).json({ error: 'Invalid email or password' });
      }

      // Generate JWT token
      const token = jwt.sign(
        { userId: user._id, email: user.email },
        SECRET_KEY,
        { expiresIn: process.env.JWT_EXPIRATION } // Token expires in 1 hour
      );
      console.log(token);

      res.json({ message: 'Login successful', token });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  });
};

// Example protected route
app.get('/protected-route', authenticateToken, (req, res) => {
  res.json({ message: 'You are authenticated', user: req.user });
});

// Start server
const PORT = 3333;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
