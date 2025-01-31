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
    userId: { type: String, unique: true },
    username: { type: String, sparse: true, unique: true },
    firstName: String,
    lastName: String,
    email: { type: String, unique: true ,required: true, },
    password: String,
    avatar: String,
    otp: String,
    otpExpires: Date,
    isVerified: { type: Boolean, default: false },
    watchTime: { type: Number, default: 0 },
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
    language: { type: String, default: 'Japanese with Subtitles' },
    notifications: { type: Boolean, default: true },
    autoplay: { type: Boolean, default: true },
    defaultQuality: { type: String, default: '1080p' },
    createdAt: { type: Date, default: Date.now }
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
            userId: uuidv4(),
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
            from: ' "Holymix" <devasish024h@gmail.com>',
            to: email,
            subject: "✨ Verify Your Email - Holymix🎌",
            html: `
            <div style="font-family: Arial, sans-serif; background: #0f172a; color: #fff; padding: 20px; border-radius: 10px; text-align: center;">
                <img src="https://i.ibb.co/Q7V4Dr3w/HOLLY.png" alt="Holymix Anime" style="width: 200px; margin-bottom: 20px;">
                <h1 style="color: #CC0000;">🌟 Welcome to Holymix Anime Streaming Site! 🌟</h1>
                <p style="font-size: 18px;">You're one step away from unlocking unlimited anime adventures! 🎬🍿</p>
                <p style="font-size: 22px; font-weight: bold; color: #facc15;">Your One-Time Password (OTP):</p>
                <div style="background: #1e293b; padding: 10px; border-radius: 8px; display: inline-block;">
                    <span style="font-size: 28px; font-weight: bold; letter-spacing: 5px; color: #CC0000;">${otp}</span>
                </div>
                <p style="font-size: 16px; margin-top: 20px;">This OTP is valid for <strong>3 minutes</strong>. Please do not share it with anyone! 🚀</p>
                <p>If you didn't request this, you can safely ignore this email. 🛡️</p>
                <hr style="border: 1px solid #374151; margin: 20px;">
                <p style="font-size: 14px; color: #9ca3af;">💌 Need help? Contact us at <a href="mailto:devasish024h@gmail.com" style="color: #facc15; text-decoration: none;">devasish024h@gmail.com</a></p>
                <p style="font-size: 14px; color: #9ca3af;">© 2025 Holymix Anime. All rights reserved.</p>
            </div>
        `,
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

        res.json({ message: 'Login successful', token, userId: user.userId });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/update-watch-history', async (req, res) => {


    const { userId, id, episodeId, title, image, number } = req.body;
    console.log(userId)
    console.log(id)
    console.log(episodeId)
    console.log(title)
    console.log(image)
    console.log(number)
    console.log("Received userId:", userId, "Type:", typeof userId);


    if (!userId || !id || !episodeId || !title || !image || !number) {
        return res.status(400).json({ error: 'Missing required fields' });
    }

    try {
        const user = await User.findOne({ userId: userId }); // No need to convert userId

        console.log("userinside update:",user);


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

// Update the recently-watched endpoint to include watchTime
app.get('/recently-watched/:userId', async (req, res) => {
    const { userId } = req.params;
    console.log(userId);

    try {
        const user = await User.findOne({ userId });
        console.log("user : ",user)

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({
            recentlyWatched: user.recentlyWatched,
            watchTime: user.watchTime  // Add this line to include watchTime
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// Add a new endpoint to update watch time
app.post('/update-watch-time', async (req, res) => {
    const { userId, timeInSeconds } = req.body;

    try {
        const user = await User.findOne({ userId });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.watchTime = (user.watchTime || 0) + timeInSeconds;
        await user.save();

        res.status(200).json({
            message: 'Watch time updated successfully',
            totalWatchTime: user.watchTime
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// Get user data
app.get('/user/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const user = await User.findOne({ userId });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Send user data without sensitive information
        res.json({
            username: user.username,
            firstName: user.firstName,
            lastName: user.lastName,
            email: user.email,
            avatar: user.avatar,
            memberSince: user.createdAt,
            watchTime: user.watchTime,
            completedAnime: user.completedAnime,
            watchlist: user.watchlist,
            language: user.language,
            notifications: user.notifications,
            autoplay: user.autoplay,
            defaultQuality: user.defaultQuality,
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Update user data
// Update user endpoint
app.put('/update-user/:userId', async (req, res) => {
    const { userId } = req.params;
    const updates = req.body;

    try {
        const user = await User.findOne({ userId });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if username is being changed and is unique
        if (updates.username && updates.username !== user.username) {
            const existingUser = await User.findOne({ username: updates.username });
            if (existingUser) {
                return res.status(400).json({ error: 'Username already taken' });
            }
        }

        // Track changed settings
        const changedSettings = [];
        if (updates.language !== user.language) changedSettings.push(`Language: ${updates.language}`);
        if (updates.defaultQuality !== user.defaultQuality) changedSettings.push(`Quality: ${updates.defaultQuality}`);
        if (updates.notifications !== user.notifications) changedSettings.push(`Notifications: ${updates.notifications ? 'Enabled' : 'Disabled'}`);
        if (updates.autoplay !== user.autoplay) changedSettings.push(`Autoplay: ${updates.autoplay ? 'Enabled' : 'Disabled'}`);

        // Update user fields
        Object.keys(updates).forEach(key => {
            if (updates[key] !== undefined) {
                user[key] = updates[key];
            }
        });

        await user.save();

        // Send email notification if settings were changed
       // Email transport configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
    },
});

// Test email configuration
transporter.verify(function (error, success) {
    if (error) {
        console.log("Email configuration error:", error);
    } else {
        console.log("Email server is ready to send messages");
    }
});

// In the update-user endpoint, update the email sending part:
if (changedSettings.length > 0 && user.email) {
    const emailContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #CC0000; text-align: center;">Your HolyMix Settings Have Been Updated</h2>
            <p>Hello ${user.firstName || user.username},</p>
            <p>The following settings have been changed in your HolyMix account:</p>
            <ul style="background: #f5f5f5; padding: 20px; border-radius: 5px;">
                ${changedSettings.map(setting => `<li style="margin: 10px 0;">${setting}</li>`).join('')}
            </ul>
            <p style="color: #666;">If you didn't make these changes, please contact support immediately.</p>
            <hr style="border: 1px solid #eee; margin: 20px 0;">
            <p style="text-align: center; color: #888; font-size: 12px;">
                Best regards,<br>HolyMix Team
            </p>
        </div>
    `;

    try {
        await transporter.sendMail({
            from: `"HolyMix" <${process.env.GMAIL_USER}>`,
            to: user.email,
            subject: '🔔 HolyMix Settings Updated',
            html: emailContent,
        });
        console.log('Settings update email sent successfully');
    } catch (emailError) {
        console.error('Error sending settings update email:', emailError);
    }
}

        res.json({
            message: 'Profile updated successfully',
            user: {
                username: user.username,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                avatar: user.avatar,
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Toggle watchlist
app.post('/toggle-watchlist', async (req, res) => {
    const { userId, animeId, title, image } = req.body;

    try {
        const user = await User.findOne({ userId });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const existingIndex = user.watchlist.findIndex(item => item.animeId === animeId);

        if (existingIndex !== -1) {
            // Remove from watchlist
            user.watchlist.splice(existingIndex, 1);
        } else {
            // Add to watchlist
            user.watchlist.push({ animeId, title, image });
        }

        await user.save();
        res.json({ message: 'Watchlist updated successfully', watchlist: user.watchlist });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Toggle completed status
app.post('/toggle-completed', async (req, res) => {
    const { userId, animeId } = req.body;

    try {
        const user = await User.findOne({ userId });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const completedIndex = user.completedAnime.indexOf(animeId);

        if (completedIndex !== -1) {
            // Remove from completed list
            user.completedAnime.splice(completedIndex, 1);
        } else {
            // Add to completed list
            user.completedAnime.push(animeId);
        }

        await user.save();
        res.json({ message: 'Completed list updated successfully', completedAnime: user.completedAnime });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Add this new endpoint after other routes
app.put('/change-password/:userId', async (req, res) => {
    const { userId } = req.params;
    const { currentPassword, newPassword } = req.body;

    try {
        const user = await User.findOne({ userId });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify current password
        if (user.password !== currentPassword) {
            return res.status(400).json({ error: 'Current password is incorrect' });
        }

        // Update password
        user.password = newPassword;
        await user.save();

        // Send email notification
        const emailContent = `
            <div style="font-family: Arial, sans-serif; background: #0f172a; color: #fff; padding: 20px; border-radius: 10px; text-align: center;">
                <img src="https://i.ibb.co/Q7V4Dr3w/HOLLY.png" alt="Holymix Anime" style="width: 200px; margin-bottom: 20px;">
                <h1 style="color: #CC0000;">🔐 Password Updated Successfully!</h1>
                <p style="font-size: 18px;">Your HolyMix account password has been changed successfully.</p>
                <p style="font-size: 16px; margin-top: 20px;">If you didn't make this change, please contact support immediately.</p>
                <hr style="border: 1px solid #374151; margin: 20px;">
                <p style="font-size: 14px; color: #9ca3af;">Need help? Contact us at devasish024h@gmail.com</p>
            </div>
        `;

        await transporter.sendMail({
            from: '"HolyMix" <devasish024h@gmail.com>',
            to: user.email,
            subject: '🔐 Password Changed - HolyMix',
            html: emailContent
        });

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
// Add these new routes to your backend

// Forgot Password Route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const otp = generateOTP();
        user.otp = otp;
        user.otpExpires = new Date(Date.now() + 180 * 1000); // 3 minutes
        await user.save();

        // Send reset email
        const emailContent = `
            <div style="font-family: Arial, sans-serif; background: #0f172a; color: #fff; padding: 20px; border-radius: 10px; text-align: center;">
                <img src="https://i.ibb.co/Q7V4Dr3w/HOLLY.png" alt="Holymix Anime" style="width: 200px; margin-bottom: 20px;">
                <h1 style="color: #CC0000;">🔐 Password Reset Request</h1>
                <p style="font-size: 18px;">Your password reset code is:</p>
                <div style="background: #1e293b; padding: 10px; border-radius: 8px; display: inline-block;">
                    <span style="font-size: 28px; font-weight: bold; letter-spacing: 5px; color: #CC0000;">${otp}</span>
                </div>
                <p style="font-size: 16px; margin-top: 20px;">This code will expire in 3 minutes.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <hr style="border: 1px solid #374151; margin: 20px;">
                <p style="font-size: 14px; color: #9ca3af;">Need help? Contact devasish024h@gmail.com</p>
            </div>
        `;

        await transporter.sendMail({
            from: '"HolyMix" <devasish024h@gmail.com>',
            to: email,
            subject: '🔐 Password Reset Request - HolyMix',
            html: emailContent
        });

        res.json({ message: 'Reset code sent to email' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Verify Reset OTP
app.post('/verify-reset-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.otp !== otp || user.otpExpires < new Date()) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        res.json({ message: 'OTP verified successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Reset Password
app.post('/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.otp !== otp || user.otpExpires < new Date()) {
            return res.status(400).json({ error: 'Invalid or expired OTP' });
        }

        user.password = newPassword;
        user.otp = null;
        user.otpExpires = null;
        await user.save();

        // Send confirmation email
        const emailContent = `
            <div style="font-family: Arial, sans-serif; background: #0f172a; color: #fff; padding: 20px; border-radius: 10px; text-align: center;">
                <img src="https://i.ibb.co/Q7V4Dr3w/HOLLY.png" alt="Holymix Anime" style="width: 200px; margin-bottom: 20px;">
                <h1 style="color: #CC0000;">✅ Password Reset Successful!</h1>
                <p style="font-size: 18px;">Your password has been successfully reset.</p>
                <p style="font-size: 16px; margin-top: 20px;">You can now log in with your new password.</p>
                <hr style="border: 1px solid #374151; margin: 20px;">
                <p style="font-size: 14px; color: #9ca3af;">Need help? Contact devasish024h@gmail.com</p>
            </div>
        `;

        await transporter.sendMail({
            from: '"HolyMix" <devasish024h@gmail.com>',
            to: email,
            subject: '✅ Password Reset Successful - HolyMix',
            html: emailContent
        });

        res.json({ message: 'Password reset successful' });
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
