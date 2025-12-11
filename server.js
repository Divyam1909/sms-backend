
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error("❌ MONGODB_URI is missing in .env file");
  process.exit(1);
}

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

// --- SCHEMAS ---

// 1. Message Schema
const messageSchema = new mongoose.Schema({
  deviceId: String,
  from: String,
  body: String,
  receivedAt: Date,
  createdAt: Date
}, { collection: 'messages' });

const Message = mongoose.model('Message', messageSchema);

// 2. User Schema (Updated with Settings)
const recurringSchema = new mongoose.Schema({
  name: String,
  amount: Number,
  date: Number
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  settings: {
    monthlyIncome: { type: Number, default: 0 },
    currency: { type: String, default: 'INR' },
    recurringExpenses: [recurringSchema]
  }
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "No token provided" });
  
    jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret', (err, decoded) => {
      if (err) return res.status(500).json({ error: "Failed to authenticate token" });
      req.userId = decoded.id;
      next();
    });
};

// --- AUTH ROUTES ---

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Username and password required" });

    // Check if user exists
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: "Username already taken" });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    res.json({ success: true, message: "User created successfully" });
  } catch (error) {
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user) return res.status(400).json({ error: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    // Generate Token
    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET || 'fallback_secret', { expiresIn: '1d' });

    res.json({ success: true, token, username: user.username });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// --- SETTINGS ROUTES ---

// Get Profile/Settings
app.get('/api/user/settings', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: "User not found" });
        res.json({ success: true, settings: user.settings });
    } catch (error) {
        res.status(500).json({ error: "Could not fetch settings" });
    }
});

// Update Profile/Settings
app.post('/api/user/settings', verifyToken, async (req, res) => {
    try {
        const { monthlyIncome, recurringExpenses } = req.body;
        const user = await User.findById(req.userId);
        
        if (!user) return res.status(404).json({ error: "User not found" });

        user.settings.monthlyIncome = monthlyIncome;
        user.settings.recurringExpenses = recurringExpenses;
        
        await user.save();
        res.json({ success: true, message: "Settings updated", settings: user.settings });
    } catch (error) {
        res.status(500).json({ error: "Could not update settings" });
    }
});

// --- DATA ROUTES ---

// Sync SMS
app.get('/api/sync-sms', async (req, res) => {
  try {
    // 1. Fetch messages
    const messages = await Message.find({}).sort({ receivedAt: -1 }).limit(50);

    if (messages.length === 0) {
      return res.json({ success: true, count: 0, messages: [] });
    }

    // 2. Extract IDs to delete
    const idsToDelete = messages.map(m => m._id);

    // 3. Delete from MongoDB
    await Message.deleteMany({ _id: { $in: idsToDelete } });

    console.log(`🔄 Synced and moved ${messages.length} messages to local.`);

    res.json({ success: true, count: messages.length, messages });

  } catch (error) {
    console.error("Sync Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 MoneyOS Server running on port ${PORT}`);
});
