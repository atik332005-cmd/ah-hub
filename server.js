const express = require("express");
const session = require("express-session");
const multer = require("multer");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!ADMIN_USER || !ADMIN_PASSWORD || !SESSION_SECRET) {
console.error("ADMIN_USER, ADMIN_PASSWORD ও SESSION_SECRET সেট করতে হবে।");
process.exit(1);
}

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

app.use(session({
secret: SESSION_SECRET,
resave: false,
saveUninitialized: false,
cookie: {
httpOnly: true,
secure: process.env.NODE_ENV === "production",
sameSite: "lax",
maxAge: 2 * 60 * 60 * 1000
}
}));

const dataDir = path.join(__dirname, "data");
const uploadDir = path.join(__dirname, "uploads");

fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const dbFile = path.join(dataDir, "files.json");

if (!fs.existsSync(dbFile)) {
fs.writeFileSync(dbFile, "[]");
}

function readFiles() {
try {
return JSON.parse(fs.readFileSync(dbFile, "utf8"));
} catch {
return [];
}
}

function saveFiles(files) {
fs.writeFileSync(dbFile, JSON.stringify(files, null, 2));
}

const allowedExtensions = new Set([
".apk", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
".ppt", ".pptx", ".txt", ".zip", ".jpg", ".jpeg", ".png"
]);

const storage = multer.diskStorage({
destination: (req, file, cb) => cb(null, uploadDir),
filename: (req, file, cb) => {
const ext = path.extname(file.originalname).toLowerCase();
cb(null, crypto.randomUUID() + ext);
}
});

const upload = multer({
storage,
limits: { fileSize: 100 * 1024 * 1024 },
fileFilter: (req, file, cb) => {
const ext = path.extname(file.originalname).toLowerCase();
if (allowedExtensions.has(ext)) return cb(null, true);
cb(new Error("এই ফাইলের ধরন অনুমোদিত নয়।"));
}
});

function requireAdmin(req, res, next) {
if (req.session && req.session.isAdmin) return next();
res.status(401).json({ error: "প্রথমে অ্যাডমিন লগইন করুন।" });
}

app.get("/api/files", (req, res) => {
const files = readFiles().map(({ id, name, description, category, size }) => ({
id, name, description, category, size
}));
res.json(files);
});

app.post(
"/api/admin/login",
rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 }),
(req, res) => {
const { username, password } = req.body || {};

if (username !== ADMIN_USER || password !== ADMIN_PASSWORD) {
  return res.status(401).json({ error: "ইউজারনেম বা পাসওয়ার্ড ভুল।" });
}

req.session.isAdmin = true;
res.json({ success: true });

}
);

app.get("/api/admin/status", (req, res) => {
res.json({ loggedIn: !!(req.session && req.session.isAdmin) });
});

app.post("/api/admin/logout", (req, res) => {
req.session.destroy(() => res.json({ success: true }));
});

app.post("/api/admin/upload", requireAdmin, upload.single("file"), (req, res) => {
if (!req.file) {
return res.status(400).json({ error: "একটি ফাইল নির্বাচন করুন।" });
}

const { name, description, category } = req.body;

const item = {
id: crypto.randomUUID(),
name: String(name || req.file.originalname).slice(0, 120),
description: String(description || "").slice(0, 500),
category: ["Apps", "PDF", "Documents", "Tools"].includes(category)
? category
: "Tools",
filename: req.file.filename,
originalName: req.file.originalname,
size: req.file.size,
createdAt: new Date().toISOString()
};

const files = readFiles();
files.unshift(item);
saveFiles(files);

res.status(201).json({
success: true,
file: {
id: item.id,
name: item.name,
description: item.description,
category: item.category,
size: item.size
}
});
});

app.get("/download/:id", (req, res) => {
const item = readFiles().find(file => file.id === req.params.id);

if (!item) return res.status(404).send("ফাইল পাওয়া যায়নি।");

const filePath = path.join(uploadDir, item.filename);

if (!fs.existsSync(filePath)) {
return res.status(404).send("ফাইলটি বর্তমানে পাওয়া যাচ্ছে না।");
}

res.download(filePath, item.originalName);
});

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use((err, req, res, next) => {
console.error(err.message);
res.status(400).json({ error: "অনুরোধ সম্পন্ন হয়নি। ফাইলের ধরন ও সাইজ পরীক্ষা করুন।" });
});

app.listen(PORT, () => {
console.log("AH Hub চলছে: port ${PORT}");
});
