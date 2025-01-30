const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const app = express();
const { v4: uuidv4 } = require('uuid');

// Middleware

app.use(cors({ origin: "*" }));
app.use(bodyParser.json());
app.use(express.json());

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


const userSchema = new mongoose.Schema({
    userId: { type: String, required: true, unique: true, default: () => uuidv4() },
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String,
    otp: String,
    otpExpires: Date,
    isVerified: { type: Boolean, default: false },

    recentlyWatched: [
        {
            id: String,
            episodeId: String,
            number: Number,
            title: String,
            image: String,

            watchedAt: { type: Date, default: Date.now }
        }
    ],
    watchlist: [
        {
            animeId: String,
            title: String,
            image: String,
        }
    ],
    completedAnime: [String],
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

        // Generate OTP **before** using it
        const otp = generateOTP();
        const otpExpires = new Date(Date.now() + 180 * 1000); // OTP expires in 30 seconds

        const newUser = new User({
            userId: new mongoose.Types.ObjectId().toString(),
            firstName,
            lastName,
            email,
            password,
            otp, // Now otp is defined
            otpExpires, // Now otpExpires is defined
        });

        await newUser.save(); // Save the user to MongoDB

        // Send response
        res.status(201).json({ message: 'User registered successfully. Check your email for OTP', userId: newUser.userId });

        // Send OTP email asynchronously
        await transporter.sendMail({
            from: 'Holymix devasish024h@gmail.com',
            to: email,
            subject: 'Verify Your Email',
            text: `Your OTP is: ${otp}`,
        });

        // Delete unverified users after 3 minutes
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
        }, 180 * 1000); // 3 minutes

    } catch (error) {
        res.status(500).json({ error: error.message });
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
            { userId: user.userId, email: user.email },
            SECRET_KEY,
            { expiresIn: process.env.JWT_EXPIRATION } // Token expires in 1 hour
        );
        console.log(token);

        res.json({ message: 'Login successful', token });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/update-watch-history', async (req, res) => {


    const { userId, id, episodeId, title, image, number } = req.body;



    if (!userId || !id || !episodeId || !title || !image || !number) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const user = await User.findOne({userId});



        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Find the entry with the same 'id'
        const existingEntryIndex = user.recentlyWatched.findIndex(entry => entry.id === id);

        if (existingEntryIndex !== -1) {
            // Update the existing entry
            const existingEntry = user.recentlyWatched[existingEntryIndex];
            existingEntry.episodeId = episodeId;
            existingEntry.title = title;
            existingEntry.image = image;
            existingEntry.number = number;
            existingEntry.watchedAt = new Date(); // Update the watched timestamp
        } else {
            // Add a new entry
            user.recentlyWatched.unshift({
                id, // Ensure the 'id' is correctly added
                episodeId,
                title,
                image,
                number,
                watchedAt: new Date(),
            });
        }

        // Ensure the array length doesn't exceed 10
        user.recentlyWatched = user.recentlyWatched.slice(0, 10);

        await user.save();
        res.status(200).json({ message: 'Watch history updated', recentlyWatched: user.recentlyWatched });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.get('/recently-watched/:userId', async (req, res) => {
    const { userId } = req.params;
    console.log(userId);

    try {
        const user = await User.findOne({ userId });
        console.log("user : ",user)

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ recentlyWatched: user.recentlyWatched });
    } catch (error) {
        res.status(500).json({ error: error.message });
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
