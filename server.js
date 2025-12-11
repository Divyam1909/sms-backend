// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { nanoid } = require('nanoid');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;

if (!JWT_SECRET || !MONGO_URI) {
  console.error('Missing MONGO_URI or JWT_SECRET in .env');
  process.exit(1);
}

app.use(cors());
app.use(express.json());

// Mongo models
// Replace existing connect call with this:
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => { console.error('MongoDB connect error', err); process.exit(1); });

const DeviceSchema = new mongoose.Schema({
  name: String,
  deviceId: String,
  token: String,
  createdAt: { type: Date, default: Date.now }
});
const Device = mongoose.model('Device', DeviceSchema);

const MessageSchema = new mongoose.Schema({
  deviceId: String,
  from: String,
  to: String,
  body: String,
  source: String,
  receivedAt: Date,
  createdAt: { type: Date, default: Date.now }
});
const Message = mongoose.model('Message', MessageSchema);

// Simple health
app.get('/', (req, res) => res.send('SMS backend running'));

// Device registration -> returns token
// Body: { name: "My Phone" }
app.post('/api/devices/register', async (req, res) => {
  try {
    const name = (req.body.name || 'unnamed-device').toString().slice(0, 64);
    const deviceId = nanoid(12);
    const token = jwt.sign({ deviceId }, JWT_SECRET, { expiresIn: '10y' });

    const device = new Device({ name, deviceId, token });
    await device.save();

    return res.json({ deviceId, token });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Auth middleware (expect Bearer <token>)
async function authMiddleware(req, res, next) {
  try {
    const auth = (req.headers.authorization || '').trim();
    if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'missing_auth' });
    const token = auth.slice(7);
    const payload = jwt.verify(token, JWT_SECRET);
    req.deviceId = payload.deviceId;
    // optional: verify device exists
    const device = await Device.findOne({ deviceId: req.deviceId, token }).lean();
    if (!device) return res.status(401).json({ error: 'invalid_device' });
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// Receive messages from device
// Body: { from, to, body, source, receivedAt } (receivedAt optional ISO/string)
app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { from, to, body, source } = req.body;
    const receivedAt = req.body.receivedAt ? new Date(req.body.receivedAt) : new Date();
    const msg = new Message({
      deviceId: req.deviceId,
      from: (from || '').toString().slice(0, 64),
      to: (to || '').toString().slice(0, 64),
      body: (body || '').toString().slice(0, 2000),
      source: (source || 'device'),
      receivedAt
    });
    await msg.save();

    // emit socket to all connected clients
    io.emit('new_message', {
      id: msg._id,
      deviceId: msg.deviceId,
      from: msg.from,
      to: msg.to,
      body: msg.body,
      source: msg.source,
      receivedAt: msg.receivedAt,
      createdAt: msg.createdAt
    });

    return res.status(200).json({ ok: true, id: msg._id });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Basic paginated messages endpoint
app.get('/api/messages', authMiddleware, async (req, res) => {
  try {
    const page = Math.max(0, parseInt(req.query.page || '0'));
    const limit = Math.min(100, parseInt(req.query.limit || '50'));
    const docs = await Message.find({ deviceId: req.deviceId })
      .sort({ receivedAt: -1 })
      .skip(page * limit)
      .limit(limit)
      .lean();
    return res.json({ messages: docs });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Socket.IO logging
io.on('connection', socket => {
  console.log('socket connected', socket.id);
  socket.on('disconnect', () => console.log('socket disconnected', socket.id));
});

server.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
