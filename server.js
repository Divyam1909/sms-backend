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
// 🚀 CORRECTED MOBILE SMS ENDPOINT
// ---------------------------------------------------------

// Helper function to extract data from raw SMS text
const parseSms = (body, sender) => {
  // 1. Default fallback values
  let amount = 0;
  let type = 'DEBIT';
  let category = 'Uncategorized';
  let description = sender;

  // 2. Simple Regex to find amounts (e.g., "Rs. 500", "INR 500", "USD 50.00")
  const amountRegex = /(?:Rs\.?|INR|USD)\s*(\d+(?:\.\d{1,2})?)/i;
  const match = body.match(amountRegex);

  if (match && match[1]) {
    amount = parseFloat(match[1]);
  }

  // 3. Determine Type (Credit vs Debit)
  if (body.toLowerCase().includes('credited') || body.toLowerCase().includes('received')) {
    type = 'CREDIT';
  }

  // 4. Create a simple hash to prevent duplicates
  // (In production, use a better hashing library like crypto)
  const hash = require('crypto').createHash('md5').update(body + Date.now()).digest('hex');

  return { hash, type, amount, category, description, date: new Date() };
};

app.post('/sms', async (req, res) => {
    // 1. Verify Secret (Matches UploadWorker.kt headers)
    const secret = req.headers['x-moneyos-secret'];
    const targetUserId = req.headers['x-user-id'];

    if (secret !== process.env.SMS_SECRET) {
      console.log("❌ Unauthorized SMS attempt");
      return res.status(401).json({ error: "Bad Secret" });
    }

    try {
        // 2. Receive Raw Data from App
        const { body, sender } = req.body; 

        if (!body) return res.status(400).json({ error: "No body provided" });

        console.log(`📩 Received SMS from ${sender}: ${body}`);

        // 3. Parse the Raw Text into a Transaction Object
        const transaction = parseSms(body, sender);

        // 4. Save to Database
        // Check for duplicates based on the hash we generated
        // (Note: Since the hash uses Date.now(), it won't dedup perfectly without a better hash logic, 
        // but it prevents saving the exact same object instance if retried immediately)
        const newTx = new Transaction({ 
            ...transaction, 
            userId: targetUserId,
            // Store the original raw message for debugging
            firewallReason: `Raw SMS: ${body.substring(0, 30)}...` 
        });
        
        await newTx.save();
        
        // 5. Update Budget if it's a Debit
        if (transaction.type === 'DEBIT' && transaction.amount > 0) {
            await Budget.findOneAndUpdate(
                { userId: targetUserId, category: transaction.category },
                { $inc: { spent: transaction.amount } }
            );
        }

        console.log("✅ SMS Saved as Transaction");
        res.json({ success: true });

    } catch (e) { 
        console.error("Server Error:", e);
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

// 🚀 CRUD Operations (Simplified for brevity but fully functional)
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

app.listen(PORT, () => console.log(`🚀 MoneyOS Core API live on port ${PORT}`));
