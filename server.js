require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 1️⃣ ENFORCE ENVIRONMENT VARIABLES (SECURITY)
if (!process.env.JWT_SECRET || !process.env.MONGO_URI) {
  console.error("❌ CRITICAL: Missing required environment variables (JWT_SECRET, MONGO_URI).");
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ Main API: Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
  });

// --- MODELS ---

const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    id: String, 
    hash: { type: String, index: true }, 
    type: { type: String, enum: ['DEBIT', 'CREDIT'], default: 'DEBIT' },
    amount: Number,
    category: String,
    description: String,
    // 3️⃣ FIX TRANSACTION DATE TYPE (DATA BUG)
    date: { type: Date, index: true },
    firewallDecision: String,
    firewallReason: String
});
transactionSchema.index({ userId: 1, date: -1 });
const Transaction = mongoose.model('Transaction', transactionSchema);

const budgetSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    category: String,
    limit: { type: Number, default: 0 },
    spent: { type: Number, default: 0 }
});
const Budget = mongoose.model('Budget', budgetSchema);

const goalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    id: String,
    name: String,
    targetAmount: Number,
    savedAmount: { type: Number, default: 0 },
    deadline: String,
    status: { type: String, default: 'On Track' }
});
const Goal = mongoose.model('Goal', goalSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  settings: {
    monthlyIncome: { type: Number, default: 0 },
    currentBalance: { type: Number, default: 0 },
    currency: { type: String, default: 'INR' },
    recurringExpenses: [{
        id: String,
        name: String,
        amount: Number,
        date: Number,
        frequency: String
    }],
    onboardingComplete: { type: Boolean, default: false }
  }
});
const User = mongoose.model('User', userSchema);

// --- AUTH MIDDLEWARE ---

// 1️⃣ FIX AUTHORIZATION HEADER VERIFICATION
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(403).json({ error: "No token provided" });
  }

  const token = auth.split(' ')[1];

  // 2️⃣ REMOVE JWT SECRET FALLBACK (SECURITY)
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.userId = decoded.id;
    next();
  });
};

// --- ROUTES ---

// Auth: Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: "Username already taken" });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.json({ success: true, message: "User created" });
  } catch (error) {
    res.status(500).json({ error: "Registration failed" });
  }
});

// Auth: Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(400).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, username: user.username });
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Data: Hydration
app.get('/api/data', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        const transactions = await Transaction.find({ userId: req.userId }).sort({ date: -1 }).limit(100);
        const budgets = await Budget.find({ userId: req.userId });
        const goals = await Goal.find({ userId: req.userId });
        res.json({ success: true, settings: user.settings, transactions, budgets, goals });
    } catch (error) {
        res.status(500).json({ error: "Fetch failed" });
    }
});

// Transactions: Create Single
app.post('/api/transactions', verifyToken, async (req, res) => {
    try {
        const { transaction } = req.body;
        const newTx = new Transaction({ ...transaction, userId: req.userId });
        await newTx.save();
        
        // 4️⃣ REMOVE BUDGET $inc MUTATION (DATA CORRUPTION RISK)
        // Automatic budget mutations are removed to ensure data integrity.
        
        res.json({ success: true, transaction: newTx });
    } catch (error) {
        res.status(500).json({ error: "Save failed" });
    }
});

// Transactions: Bulk Sync
app.post('/api/transactions/sync', verifyToken, async (req, res) => {
    try {
        const { transactions } = req.body;
        const ops = transactions.map(tx => ({
            updateOne: {
                filter: { userId: req.userId, hash: tx.hash },
                update: { $setOnInsert: { ...tx, userId: req.userId } },
                upsert: true
            }
        }));
        const result = await Transaction.bulkWrite(ops);
        
        // 4️⃣ REMOVE BUDGET $inc MUTATION (DATA CORRUPTION RISK)
        // Automatic budget mutations are removed to ensure data integrity.

        res.json({ success: true, added: result.upsertedCount });
    } catch (error) {
        res.status(500).json({ error: "Sync failed" });
    }
});

// Onboarding
app.post('/api/onboarding', verifyToken, async (req, res) => {
    try {
        const { monthlyIncome, currentBalance, recurringExpenses, initialBudgets } = req.body;
        const user = await User.findById(req.userId);
        user.settings = { ...user.settings, monthlyIncome, currentBalance, recurringExpenses, onboardingComplete: true };
        await user.save();
        if (initialBudgets) {
            await Budget.deleteMany({ userId: req.userId });
            await Budget.insertMany(initialBudgets.map(b => ({ ...b, userId: req.userId })));
        }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: "Onboarding failed" });
    }
});

// Budgets
app.post('/api/budgets', verifyToken, async (req, res) => {
    try {
        const { budgets } = req.body;
        for (const b of budgets) {
            const filter = b._id ? { _id: b._id } : { userId: req.userId, category: b.category };
            await Budget.findOneAndUpdate(filter, { ...b, userId: req.userId }, { upsert: true });
        }
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: "Budget update failed" });
    }
});

app.listen(PORT, () => console.log(`🚀 Main API running on port ${PORT}`));