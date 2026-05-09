require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();

// ── Config ────────────────────────────────────────────────────────────────────
const PORT       = process.env.PORT       || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'change_me_in_production';
const MONGO_URI  = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error('❌ MONGO_URI is not set in .env — please set it and restart.');
  process.exit(1);
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());

// ── MongoDB Connection ────────────────────────────────────────────────────────
mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ Alpha Ai MongoDB Atlas Connected'))
  .catch(err => { console.error('❌ DB Error:', err.message); process.exit(1); });

// ── Email Transporter ─────────────────────────────────────────────────────────
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ── Models ────────────────────────────────────────────────────────────────────

// User Schema
const userSchema = new mongoose.Schema({
  name:         { type: String, required: true },
  email:        { type: String, unique: true, lowercase: true, required: true },
  phone:        String,
  professional: String,
  password:     { type: String, required: true },
  pptCount:     { type: Number, default: 0 },
  downloadCount:{ type: Number, default: 0 },
  extraPacks:   { type: Number, default: 0 },
  isVerified:   { type: Boolean, default: false },
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// OTP Schema (TTL index — auto-deletes after 10 min)
const otpSchema = new mongoose.Schema({
  email:     { type: String, lowercase: true, required: true },
  otp:       { type: String, required: true },
  type:      { type: String, enum: ['verify', 'forgot'], default: 'verify' },
  createdAt: { type: Date, default: Date.now, expires: 600 },
});
const OTP = mongoose.model('OTP', otpSchema);

// PPT History Schema — stores every generated presentation
const pptHistorySchema = new mongoose.Schema({
  userId:       { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  topic:        { type: String, required: true },
  slideCount:   { type: Number, default: 5 },
  themeName:    String,
  layoutId:     { type: Number, default: 1 },
  palette:      { type: mongoose.Schema.Types.Mixed, default: {} },
  slides:       { type: mongoose.Schema.Types.Mixed, default: [] },
}, { timestamps: true });
const PptHistory = mongoose.model('PptHistory', pptHistorySchema);

// ── Helpers ────────────────────────────────────────────────────────────────────
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOtpEmail(email, otp, subject) {
  const html = `
    <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;background:#f9f9f9;padding:28px;border-radius:12px;border:1px solid #e5e7eb;">
      <h2 style="color:#4F46E5;margin-bottom:6px;">Alpha Ai PPT Studio</h2>
      <p style="color:#374151;font-size:14px;">${subject}</p>
      <div style="background:#4F46E5;color:#fff;font-size:32px;font-weight:900;letter-spacing:8px;padding:18px;border-radius:8px;text-align:center;margin:20px 0;">${otp}</div>
      <p style="color:#6b7280;font-size:12px;">This OTP expires in 10 minutes. Do not share it with anyone.</p>
    </div>`;
  await transporter.sendMail({
    from: `"Alpha Ai" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: `Alpha Ai — ${subject}`,
    html,
  });
}

function signToken(user) {
  return jwt.sign(
    { id: user._id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized — no token provided' });
  }
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized — invalid or expired token' });
  }
}

// ── Auth Routes ────────────────────────────────────────────────────────────────

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required.' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) {
      if (!existing.isVerified) {
        // Resend OTP
        const otp = generateOTP();
        await OTP.deleteMany({ email: email.toLowerCase(), type: 'verify' });
        await OTP.create({ email: email.toLowerCase(), otp, type: 'verify' });
        await sendOtpEmail(email, otp, 'Verify your email');
        return res.json({ message: 'Account exists but not verified. OTP resent to your email.' });
      }
      return res.status(409).json({ error: 'Email already registered.' });
    }

    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email: email.toLowerCase(), password: hashed });
    const otp = generateOTP();
    await OTP.create({ email: email.toLowerCase(), otp, type: 'verify' });
    await sendOtpEmail(email, otp, 'Verify your Alpha Ai account');
    res.json({ message: 'Account created! Check your email for the OTP to verify.' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

// POST /api/auth/verify-otp
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp, type } = req.body;
    const record = await OTP.findOne({ email: email.toLowerCase(), otp, type: type || 'verify' });
    if (!record) return res.status(400).json({ error: 'Invalid or expired OTP.' });

    if (type === 'forgot') {
      // Return a short-lived reset token
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) return res.status(404).json({ error: 'User not found.' });
      await OTP.deleteMany({ email: email.toLowerCase(), type: 'forgot' });
      const resetToken = jwt.sign({ id: user._id, purpose: 'reset' }, JWT_SECRET, { expiresIn: '15m' });
      return res.json({ resetToken });
    }

    // Email verification
    const user = await User.findOneAndUpdate(
      { email: email.toLowerCase() },
      { isVerified: true },
      { new: true }
    );
    await OTP.deleteMany({ email: email.toLowerCase(), type: 'verify' });
    const token = signToken(user);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, pptCount: user.pptCount, downloadCount: user.downloadCount, extraPacks: user.extraPacks } });
  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/auth/resend-otp
app.post('/api/auth/resend-otp', async (req, res) => {
  try {
    const { email, type } = req.body;

    // Special case: post-password-reset security notification (no OTP needed, just a notification)
    if (type === 'resetConfirm') {
      const user = await User.findOne({ email: email.toLowerCase() });
      // Send regardless – don't leak user existence
      const notifyHtml = `
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;background:#f9f9f9;padding:28px;border-radius:12px;border:1px solid #e5e7eb;">
          <h2 style="color:#4F46E5;margin-bottom:6px;">Alpha Ai PPT Studio</h2>
          <p style="color:#374151;font-size:14px;">Your account password was successfully changed.</p>
          <div style="background:#dcfce7;color:#166534;font-size:15px;font-weight:600;padding:14px 18px;border-radius:8px;margin:18px 0;border:1px solid #bbf7d0;">
            ✅ Password changed successfully
          </div>
          <p style="color:#374151;font-size:13px;">If you did not make this change, please contact us immediately at <a href="tel:+918318628430">+91 83186 28430</a>.</p>
          <p style="color:#6b7280;font-size:12px;">Time: ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</p>
        </div>`;
      try {
        await transporter.sendMail({
          from: `"Alpha Ai" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Alpha Ai — Password Changed Successfully',
          html: notifyHtml,
        });
      } catch (mailErr) {
        console.warn('Notification email failed:', mailErr.message);
      }
      return res.json({ message: 'Notification sent.' });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: 'No account found with this email.' });
    const otp = generateOTP();
    await OTP.deleteMany({ email: email.toLowerCase(), type: type || 'verify' });
    await OTP.create({ email: email.toLowerCase(), otp, type: type || 'verify' });
    const subject = type === 'forgot' ? 'Reset your password' : 'Verify your email';
    await sendOtpEmail(email, otp, subject);
    res.json({ message: 'OTP resent successfully.' });
  } catch (err) {
    console.error('Resend OTP error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'Invalid email or password.' });
    if (!user.isVerified) return res.status(403).json({ error: 'Please verify your email first.', needsVerification: true });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid email or password.' });
    const token = signToken(user);
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, pptCount: user.pptCount, downloadCount: user.downloadCount, extraPacks: user.extraPacks } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/auth/forgot-password
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(404).json({ error: 'No account found with this email.' });
    const otp = generateOTP();
    await OTP.deleteMany({ email: email.toLowerCase(), type: 'forgot' });
    await OTP.create({ email: email.toLowerCase(), otp, type: 'forgot' });
    await sendOtpEmail(email, otp, 'Reset your password');
    res.json({ message: 'Password reset OTP sent to your email.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/auth/reset-password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { resetToken, newPassword } = req.body;
    if (!resetToken || !newPassword) return res.status(400).json({ error: 'Token and new password required.' });
    if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    const decoded = jwt.verify(resetToken, JWT_SECRET);
    if (decoded.purpose !== 'reset') return res.status(400).json({ error: 'Invalid reset token.' });
    const hashed = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(decoded.id, { password: hashed });
    res.json({ message: 'Password reset successfully. You can now sign in.' });
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' });
    }
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/auth/me — get current user data (for manual auth)
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ user: { id: user._id, name: user.name, email: user.email, pptCount: user.pptCount, downloadCount: user.downloadCount, extraPacks: user.extraPacks } });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── PPT Usage Routes ───────────────────────────────────────────────────────────

// POST /api/ppt/increment-count — called after successful generation
app.post('/api/ppt/increment-count', authMiddleware, async (req, res) => {
  try {
    const MAX_FREE = 6;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (user.pptCount >= MAX_FREE + (user.extraPacks * 5)) {
      return res.status(403).json({ error: 'Generation limit reached.', limitReached: true });
    }
    user.pptCount += 1;
    await user.save();
    res.json({ pptCount: user.pptCount, downloadCount: user.downloadCount, extraPacks: user.extraPacks });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/ppt/increment-download — called after download
app.post('/api/ppt/increment-download', authMiddleware, async (req, res) => {
  try {
    const MAX_FREE_DOWN = 6;
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (user.downloadCount >= MAX_FREE_DOWN + (user.extraPacks * 5)) {
      return res.status(403).json({ error: 'Download limit reached.', limitReached: true });
    }
    user.downloadCount += 1;
    await user.save();
    res.json({ pptCount: user.pptCount, downloadCount: user.downloadCount, extraPacks: user.extraPacks });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// POST /api/ppt/save — save presentation to MongoDB
app.post('/api/ppt/save', authMiddleware, async (req, res) => {
  try {
    const { topic, slideCount, themeName, layoutId, palette, slides } = req.body;
    if (!topic) return res.status(400).json({ error: 'Topic is required.' });
    const record = await PptHistory.create({
      userId: req.user.id,
      topic,
      slideCount: slideCount || slides?.length || 5,
      themeName,
      layoutId: layoutId || 1,
      palette: palette || {},
      slides: slides || [],
    });
    res.json({ message: 'Presentation saved.', id: record._id });
  } catch (err) {
    console.error('Save PPT error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/ppt/history — get user's saved presentations
app.get('/api/ppt/history', authMiddleware, async (req, res) => {
  try {
    const history = await PptHistory.find({ userId: req.user.id })
      .select('topic slideCount themeName layoutId palette createdAt')
      .sort({ createdAt: -1 })
      .limit(20);
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// GET /api/ppt/history/:id — load a specific presentation with all slide data
app.get('/api/ppt/history/:id', authMiddleware, async (req, res) => {
  try {
    const record = await PptHistory.findOne({ _id: req.params.id, userId: req.user.id });
    if (!record) return res.status(404).json({ error: 'Presentation not found.' });
    res.json({ record });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// DELETE /api/ppt/history/:id
app.delete('/api/ppt/history/:id', authMiddleware, async (req, res) => {
  try {
    await PptHistory.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ message: 'Deleted.' });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Admin Routes ───────────────────────────────────────────────────────────────

// POST /api/admin/grant-pack — manually give a user more download packs (after payment)
app.post('/api/admin/grant-pack', async (req, res) => {
  try {
    const { adminKey, email, packs } = req.body;
    if (adminKey !== process.env.ADMIN_KEY) return res.status(403).json({ error: 'Forbidden.' });
    const user = await User.findOneAndUpdate(
      { email: email.toLowerCase() },
      { $inc: { extraPacks: packs || 1 } },
      { new: true }
    );
    if (!user) return res.status(404).json({ error: 'User not found.' });
    res.json({ message: `Granted ${packs || 1} pack(s) to ${email}.`, extraPacks: user.extraPacks });
  } catch (err) {
    res.status(500).json({ error: 'Server error.' });
  }
});

// ── Health Check ───────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', service: 'Alpha Ai Backend', version: '2.0' }));

// ── Start Server ───────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`🚀 Alpha Ai Backend running on port ${PORT}`));
