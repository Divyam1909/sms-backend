require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// 1️⃣ ENFORCE ENVIRONMENT VARIABLES
if (!process.env.JWT_SECRET || !process.env.MONGO_URI || !process.env.SMS_SECRET) {
  console.error("❌ CRITICAL: Missing required environment variables (JWT_SECRET, MONGO_URI, SMS_SECRET).");
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MoneyOS Main API: Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB Connection Error:', err);
    process.exit(1);
  });

// --- MODELS ---

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  settings: {
    monthlyIncome: { type: Number, default: 0 },
    currentBalance: { type: Number, default: 0 },
    onboardingComplete: { type: Boolean, default: false },
    recurringExpenses: { type: Array, default: [] }
  }
});
const User = mongoose.model('User', userSchema);

const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    id: String, 
    hash: { type: String, index: true }, 
    type: { type: String, enum: ['DEBIT', 'CREDIT'], default: 'DEBIT' },
    amount: Number,
    category: String,
    sender: String, // Added sender field for history display
    description: String,
    date: { type: Date, default: Date.now },
    firewallDecision: { type: String, default: 'ALLOW' },
    firewallReason: { type: String, default: 'Manual' }
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
    name: String,
    targetAmount: Number,
    savedAmount: { type: Number, default: 0 },
    deadline: String,
    status: String
});
const Goal = mongoose.model('Goal', goalSchema);

// --- CATEGORY INTELLIGENCE ---
const CATEGORY_KEYWORDS = {
  'Food': ['ZOMATO', 'SWIGGY', 'DOMINOS', 'PIZZA', 'BURGER', 'KFC', 'MCDONALD', 'STARBUCKS'],
  'Transport': ['UBER', 'OLA', 'RAPIDO', 'IRCTC', 'METRO', 'FUEL', 'PETROL', 'SHELL', 'BPCL'],
  'Shopping': ['AMAZON', 'FLIPKART', 'MYNTRA', 'AJIO', 'ZARA', 'H&M', 'RELIANCE', 'TATA'],
  'Grocery': ['BLINKIT', 'ZEPTO', 'BIGBASKET', 'DMART', 'GROFERS', 'NATURES'],
  'Utilities': ['JIO', 'AIRTEL', 'VI', 'BSNL', 'ACT', 'BESCOM', 'POWER', 'GAS'],
  'Bank': ['HDFC', 'ICICI', 'SBI', 'AXIS', 'KOTAK', 'PNB', 'BOB', 'PAYTM', 'GPAY', 'PHONEPE']
};

const detectCategory = (sender, body) => {
  const text = (sender + " " + body).toUpperCase();
  
  for (const [category, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
    if (keywords.some(keyword => text.includes(keyword))) {
      return category;
    }
  }
  return 'Uncategorized';
};

// --- AUTH MIDDLEWARE ---

const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(403).json({ error: "No token provided" });
  const token = auth.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Unauthorized access" });
    req.userId = decoded.id;
    next();
  });
};

// --- ROUTES ---

// 🚀 REGISTER & LOGIN
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ success: true });
  } catch (e) { res.status(400).json({ error: "Username already exists" }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ success: true, token, username: user.username });
  } catch (e) { res.status(500).json({ error: "Server error" }); }
});

// ---------------------------------------------------------
// 🚀 MOBILE SMS ENDPOINT (UPDATED)
// ---------------------------------------------------------

const parseSms = (body, sender) => {
  let amount = 0;
  let type = 'DEBIT';
  let description = sender;

  // 1. Amount Regex
  const amountRegex = /(?:Rs\.?|INR|USD)\s*(\d+(?:\.\d{1,2})?)/i;
  const match = body.match(amountRegex);
  if (match && match[1]) amount = parseFloat(match[1]);

  // 2. Type Detection
  if (body.toLowerCase().includes('credited') || body.toLowerCase().includes('received')) {
    type = 'CREDIT';
  }

  // 3. Smart Category Detection
  const category = detectCategory(sender, body);

  // 4. Stable Hash (Sender + Body ensures duplicates are caught even if retried later)
  const hash = crypto.createHash('md5').update(sender + body).digest('hex');

  return { hash, type, amount, category, description, date: new Date() };
};

app.post('/sms', async (req, res) => {
    const secret = req.headers['x-moneyos-secret'];
    const targetUserId = req.headers['x-user-id'];

    if (secret !== process.env.SMS_SECRET) {
      console.log("❌ Unauthorized SMS attempt");
      return res.status(401).json({ error: "Bad Secret" });
    }

    try {
        const { body, sender } = req.body; 
        if (!body) return res.status(400).json({ error: "No body provided" });

        console.log(`📩 Received SMS from ${sender}: ${body}`);

        const transaction = parseSms(body, sender);

        // Check for duplicates
        const existing = await Transaction.findOne({ userId: targetUserId, hash: transaction.hash });
        if (existing) {
            console.log("⚠️ Duplicate SMS ignored.");
            return res.json({ success: true, status: 'duplicate' });
        }

        const newTx = new Transaction({ 
            ...transaction, 
            userId: targetUserId,
            sender: sender, // Save sender for history UI
            firewallReason: `Raw SMS: ${body.substring(0, 30)}...` 
        });
        
        await newTx.save();
        
        if (transaction.type === 'DEBIT' && transaction.amount > 0) {
            await Budget.findOneAndUpdate(
                { userId: targetUserId, category: transaction.category },
                { $inc: { spent: transaction.amount } }
            );
        }

        console.log(`✅ Transaction saved: ${transaction.category} - ${transaction.amount}`);
        res.json({ success: true });

    } catch (e) { 
        console.error("Server Error:", e);
        res.status(500).json({ error: e.message }); 
    }
});

// 🚀 NEW ENDPOINT: FETCH RECENT SMS HISTORY
app.get('/sms/recent', async (req, res) => {
    const secret = req.headers['x-moneyos-secret'];
    const targetUserId = req.headers['x-user-id'];

    if (secret !== process.env.SMS_SECRET) return res.status(401).json({ error: "Bad Secret" });

    try {
        const transactions = await Transaction.find({ userId: targetUserId })
            .sort({ date: -1 })
            .limit(20)
            .select('hash sender amount category type date'); // Select only needed fields
            
        res.json({ success: true, transactions });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// 🚀 FETCH ALL DATA
app.get('/api/data', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        const transactions = await Transaction.find({ userId: req.userId }).sort({ date: -1 }).limit(50);
        const budgets = await Budget.find({ userId: req.userId });
        const goals = await Goal.find({ userId: req.userId });
        res.json({ success: true, settings: user.settings, transactions, budgets, goals });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 🚀 ONBOARDING
app.post('/api/onboarding', verifyToken, async (req, res) => {
    try {
        const { monthlyIncome, currentBalance, recurringExpenses, initialBudgets } = req.body;
        await User.findByIdAndUpdate(req.userId, {
            settings: { monthlyIncome, currentBalance, recurringExpenses, onboardingComplete: true }
        });
        const budgetsWithUser = initialBudgets.map(b => ({ ...b, userId: req.userId }));
        await Budget.insertMany(budgetsWithUser);
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// 🚀 CRUD Operations
app.post('/api/transactions', verifyToken, async (req, res) => {
    const tx = new Transaction({ ...req.body.transaction, userId: req.userId });
    await tx.save();
    if (tx.type === 'DEBIT') {
        await Budget.findOneAndUpdate({ userId: req.userId, category: tx.category }, { $inc: { spent: tx.amount } });
    }
    res.json({ success: true });
});

app.post('/api/budgets', verifyToken, async (req, res) => {
    for (const b of req.body.budgets) {
        await Budget.findOneAndUpdate(
            { userId: req.userId, category: b.category },
            { $set: { limit: b.limit, spent: b.spent } },
            { upsert: true }
        );
    }
    res.json({ success: true });
});

app.post('/api/goals', verifyToken, async (req, res) => {
    const goal = new Goal({ ...req.body.goal, userId: req.userId });
    await goal.save();
    res.json({ success: true });
});

app.get('/api/user/settings', verifyToken, async (req, res) => {
    const user = await User.findById(req.userId);
    res.json({ success: true, settings: user.settings });
});

app.post('/api/user/settings', verifyToken, async (req, res) => {
    await User.findByIdAndUpdate(req.userId, { 'settings.monthlyIncome': req.body.monthlyIncome, 'settings.recurringExpenses': req.body.recurringExpenses });
    res.json({ success: true });
});
// 🚀 HEALTH CHECK
app.get('/health', (req, res) => res.status(200).send('OK'));

app.listen(PORT, () => console.log(`🚀 MoneyOS Core API live on port ${PORT}`));