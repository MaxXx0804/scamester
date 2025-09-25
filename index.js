require('dotenv').config();
const express = require('express');
const bcrypt  = require('bcrypt');
const cors    = require('cors');
const db      = require('./database');
const nodemailer = require('nodemailer');

const app = express();
app.use(cors());
app.use(express.json());

const SALT_ROUNDS = 10;
function sanitizeEmail(email) { return email.replace(/\./g, ','); }
function generateCode() { return Math.floor(100000 + Math.random() * 900000).toString(); }

port = process.env.PORT || 3000;

// ✅ Configure email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

//#region ENDPOINTS





//#region RESEND CODE
// --- RESEND VERIFICATION CODE ---
app.post("/resend", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required." });

  try {
    const safeEmail = sanitizeEmail(email);

    // Check if there's a pending signup
    const snap = await db.ref(`pending/${safeEmail}`).once("value");
    if (!snap.exists()) return res.status(404).json({ error: "Pending signup not found." });

    const newCode = generateCode();
    const newExpires = Date.now() + 10 * 60 * 1000; // 10 minutes

    // Update the pending user with new code & expiration
    await db.ref(`pending/${safeEmail}`).update({
      verificationCode: newCode,
      expiresAt: newExpires
    });

    // Send the new code
    await transporter.sendMail({
      from: `"Scamester" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your New Verification Code",
      text: `Your new verification code is: ${newCode}\n\nIt will expire in 10 minutes.`
    });

    res.json({ status: "verification_resent" });
  } catch (err) {
    console.error("Resend error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

//*RESEND password reset code
app.post("/resend-reset", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required." });

  try {
    const safeEmail = sanitizeEmail(email);

    // ✅ Check if there's an existing password reset request
    const snap = await db.ref(`password_resets/${safeEmail}`).once("value");
    if (!snap.exists())
      return res.status(404).json({ error: "No active password reset found." });

    // ✅ Generate a new code and expiration (10 minutes)
    const newCode = generateCode();
    const newExpires = Date.now() + 10 * 60 * 1000;

    // ✅ Update the reset request
    await db.ref(`password_resets/${safeEmail}`).update({
      resetCode: newCode,
      expiresAt: newExpires,
    });

    // ✅ Send email with the new code
    await transporter.sendMail({
      from: `"Scamester" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your New Password Reset Code",
      text: `Your new password reset code is: ${newCode}\n\nIt will expire in 10 minutes.`,
    });

    res.json({ status: "reset_code_resent" });
  } catch (err) {
    console.error("Resend Reset Error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});
//#endregion





//#region PASSWORD RESET
app.post("/reset-password", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email required." });

  try {
    const safeEmail = sanitizeEmail(email);

    // Check if user exists
    const userSnap = await db.ref(`users/${safeEmail}`).once("value");
    if (!userSnap.exists())
      return res.status(404).json({ error: "User not found." });

    // Generate reset code & expiration (10 minutes)
    const resetCode = generateCode();
    const expiresAt = Date.now() + 10 * 60 * 1000;

    // Store in temporary "password_resets" node
    await db.ref(`password_resets/${safeEmail}`).set({
      email,
      resetCode,
      expiresAt,
    });

    // Send email
    await transporter.sendMail({
      from: `"Scamester" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Password Reset Code",
      text: `Your password reset code is: ${resetCode}\n\nThis code will expire in 10 minutes.`,
    });

    res.json({ status: "reset_code_sent" });
  } catch (err) {
    console.error("Reset Password Error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});
//#endregion


//#region VERIFICATION
app.post("/reset-password/verify", async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code)
    return res.status(400).json({ error: "Email and code required." });

  try {
    const safeEmail = sanitizeEmail(email);

    // 🔎 Check if a reset request exists
    const resetSnap = await db.ref(`password_resets/${safeEmail}`).once("value");
    if (!resetSnap.exists())
      return res.status(404).json({ error: "No reset request found." });

    const resetData = resetSnap.val();

    // ⏳ Check expiration
    if (Date.now() > resetData.expiresAt)
      return res.status(410).json({ error: "Reset code expired." });

    // ✅ Check code match
    if (resetData.resetCode !== code)
      return res.status(401).json({ error: "Invalid reset code." });

    // 👉 If everything is valid
    res.json({ status: "code_verified" });
  } catch (err) {
    console.error("Reset Code Verification Error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});


app.post("/reset-password/update", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and new password required." });

  try {
    const safeEmail = sanitizeEmail(email);

    // 🔎 Check if a valid reset request still exists
    const resetSnap = await db.ref(`password_resets/${safeEmail}`).once("value");
    if (!resetSnap.exists())
      return res.status(404).json({ error: "No active reset request found." });

    const resetData = resetSnap.val();

    // ⏳ Double-check expiration
    if (Date.now() > resetData.expiresAt)
      return res.status(410).json({ error: "Reset code expired." });

    // 🔐 Hash the new password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // ✅ Update user's password
    await db.ref(`users/${safeEmail}`).update({
      password: hashedPassword
    });

    // 🗑️ Remove reset request to prevent reuse
    await db.ref(`password_resets/${safeEmail}`).remove();

    res.json({ status: "password_updated" });
  } catch (err) {
    console.error("Reset Password Update Error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});



// Move data from "pending" → "users" if code matches
app.post("/verify", async (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).json({ error: "Email & code required." });

  try {
    const safeEmail = sanitizeEmail(email);
    const snap = await db.ref(`pending/${safeEmail}`).once("value");
    if (!snap.exists()) return res.status(404).json({ error: "No pending signup found." });

    const pendingUser = snap.val();
    if (Date.now() > pendingUser.expiresAt) return res.status(410).json({ error: "Code expired." });
    if (pendingUser.verificationCode !== code) return res.status(401).json({ error: "Invalid code." });

    // Add to users collection
    await db.ref(`users/${safeEmail}`).set({
      email: pendingUser.email,
      password: pendingUser.password,
      createdAt: Date.now()
    });

    // Remove from pending
    await db.ref(`pending/${safeEmail}`).remove();

    res.json({ status: "verified" });
  } catch (err) {
    console.error("Verify error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});
//#endregion

//#region SIGNUP & LOGIN
// Hash password, generate code, store in "pending", send email
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email & password required." });

  try {
    const safeEmail = sanitizeEmail(email);

    // Check if already registered
    const exists = await db.ref(`users/${safeEmail}`).once("value");
    if (exists.exists()) return res.status(409).json({ error: "Email already registered." });

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const verificationCode = generateCode();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

    // Store in a temporary "pending" node
    await db.ref(`pending/${safeEmail}`).set({
      email,
      password: hashedPassword,
      verificationCode,
      expiresAt
    });

    // Send code
    await transporter.sendMail({
      from: `"Scamester" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your Verification Code",
      text: `Your verification code is: ${verificationCode}\n\nIt will expire in 10 minutes.`
    });

    res.json({ status: "verification_sent" });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});

// --- VERIFY CODE ---


// --- LOGIN ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email & password required." });

  try {
    const safeEmail = sanitizeEmail(email);
    const snap = await db.ref(`users/${safeEmail}`).once("value");
    if (!snap.exists()) return res.status(404).json({ error: "User not found." });

    const user = snap.val();
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid password." });

    res.json({ status: "login_success" });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error." });
  }
});
//#endregion
//#endregion
app.listen(port, () => {
  console.log(`Emoji Quiz API running at http://localhost:${port}`);
});
