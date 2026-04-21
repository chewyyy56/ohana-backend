const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

/* -------------------------
 * Schemas
 * ------------------------- */
const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, required: true, lowercase: true, trim: true },
    email: { type: String, default: "" },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["owner", "admin", "staff"], default: "staff" },
  },
  { timestamps: true }
);

const inventorySchema = new mongoose.Schema(
  {
    items: { type: mongoose.Schema.Types.Mixed, required: true },
  },
  { timestamps: true }
);

const orderSchema = new mongoose.Schema(
  {
    createdAt: { type: Date, default: Date.now },
    productId: Number,
    productName: String,
    size: String,
    revenue: { type: Number, default: 0 },
    cogs: { type: Number, default: 0 },
    needed: { type: mongoose.Schema.Types.Mixed, default: {} },
    orderedBy: { type: String, default: "" },
  },
  { timestamps: true }
);

const alertSchema = new mongoose.Schema(
  {
    materialKey: { type: String, required: true },
    message: { type: String, required: true },
    severity: { type: String, default: "Yellow" },
    createdBy: { type: String, default: "" },
    cleared: { type: Boolean, default: false },
    clearedAt: { type: Date, default: null },
    clearedBy: { type: String, default: "" },
  },
  { timestamps: true }
);

const supplierDeliverySchema = new mongoose.Schema(
  {
    supplier: { type: String, required: true },
    item: { type: String, required: true },
    qty: { type: Number, required: true },
    cost: { type: Number, required: true },
    createdBy: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Inventory = mongoose.model("Inventory", inventorySchema);
const Order = mongoose.model("Order", orderSchema);
const Alert = mongoose.model("Alert", alertSchema);
const SupplierDelivery = mongoose.model("SupplierDelivery", supplierDeliverySchema);

/* -------------------------
 * Defaults
 * ------------------------- */
const INITIAL_INVENTORY = {
  coffeeBeans: 5000,
  matchaPowder: 1000,
  cocoaPowder: 1000,
  milk: 10000,
  sugarSyrup: 5000,
  condensedMilk: 2000,
  cups12oz: 50,
  cups16oz: 50,
  cups22oz: 50,
  lids: 200,
  straws: 200,
};

/* -------------------------
 * Auth helpers
 * ------------------------- */
function signToken(user) {
  return jwt.sign(
    { id: user._id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ ok: false, message: "Missing token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ ok: false, message: "Invalid token" });
  }
}

function allowRoles(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ ok: false, message: "Unauthorized" });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ ok: false, message: "Forbidden" });
    }
    next();
  };
}

/* -------------------------
 * Seed data
 * ------------------------- */
async function ensureSeedData() {
  const inv = await Inventory.findOne();
  if (!inv) {
    await Inventory.create({ items: { ...INITIAL_INVENTORY } });
  }
}

/* -------------------------
 * Basic routes
 * ------------------------- */
app.get("/", (_req, res) => {
  res.json({ ok: true });
});

app.get("/api/health", (_req, res) => {
  const mongoState = mongoose.connection.readyState; // 1 = connected
  res.json({ ok: true, mongoState });
});

/* -------------------------
 * Auth routes
 * ------------------------- */
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, email = "", password } = req.body || {};
    const uname = String(username || "").trim().toLowerCase();

    if (!uname || !password) {
      return res.status(400).json({ ok: false, message: "Username and password are required" });
    }

    const exists = await User.findOne({ username: uname });
    if (exists) return res.status(409).json({ ok: false, message: "Username already exists" });

    const passwordHash = await bcrypt.hash(String(password), 10);

    const user = await User.create({
      username: uname,
      email: String(email || "").trim(),
      role: "staff",
      passwordHash,
    });

    const token = signToken(user);
    res.status(201).json({
      ok: true,
      token,
      user: { id: user._id, username: user.username, role: user.role, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const uname = String(username || "").trim().toLowerCase();
    const pass = String(password || "");

    const user = await User.findOne({ username: uname });
    if (!user) return res.status(401).json({ ok: false, message: "Invalid username or password" });

    const match = await bcrypt.compare(pass, user.passwordHash);
    if (!match) return res.status(401).json({ ok: false, message: "Invalid username or password" });

    const token = signToken(user);

    res.json({
      ok: true,
      token,
      user: { id: user._id, username: user.username, role: user.role, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

/* -------------------------
 * Inventory routes
 * ------------------------- */
app.get("/api/inventory", auth, async (_req, res) => {
  try {
    const inv = await Inventory.findOne();
    res.json({ ok: true, inventory: inv?.items || {} });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.patch("/api/inventory/restock", auth, allowRoles("admin", "owner"), async (req, res) => {
  try {
    const { materialKey, qty } = req.body || {};
    const nQty = Number(qty);

    if (!materialKey || !Number.isFinite(nQty) || nQty <= 0) {
      return res.status(400).json({ ok: false, message: "materialKey and positive qty are required" });
    }

    const inv = await Inventory.findOne();
    if (!inv) return res.status(404).json({ ok: false, message: "Inventory not found" });

    inv.items[materialKey] = Number(inv.items[materialKey] || 0) + nQty;
    inv.markModified("items");
    await inv.save();

    res.json({ ok: true, inventory: inv.items });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

/* -------------------------
 * Orders routes
 * ------------------------- */
app.get("/api/orders", auth, allowRoles("owner", "admin"), async (_req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 }).limit(1000);
    res.json({ ok: true, orders });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/api/orders", auth, async (req, res) => {
  try {
    const { productId, productName, size, revenue = 0, cogs = 0, needed = {} } = req.body || {};

    const inv = await Inventory.findOne();
    if (!inv) return res.status(404).json({ ok: false, message: "Inventory not found" });

    for (const [k, amt] of Object.entries(needed || {})) {
      const required = Number(amt || 0);
      if (required <= 0) continue;
      const onHand = Number(inv.items[k] || 0);
      if (onHand < required) {
        return res.status(400).json({ ok: false, message: `Not enough ${k}` });
      }
    }

    for (const [k, amt] of Object.entries(needed || {})) {
      const required = Number(amt || 0);
      if (required <= 0) continue;
      inv.items[k] = Math.max(0, Number(inv.items[k] || 0) - required);
    }
    inv.markModified("items");
    await inv.save();

    const order = await Order.create({
      createdAt: new Date(),
      productId,
      productName,
      size,
      revenue: Number(revenue || 0),
      cogs: Number(cogs || 0),
      needed,
      orderedBy: req.user.username,
    });

    res.status(201).json({ ok: true, order, inventory: inv.items });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

/* -------------------------
 * Alerts routes
 * ------------------------- */
app.get("/api/alerts", auth, allowRoles("admin", "owner"), async (_req, res) => {
  try {
    const alerts = await Alert.find({ cleared: false }).sort({ createdAt: -1 });
    res.json({ ok: true, alerts });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/api/alerts", auth, async (req, res) => {
  try {
    const { materialKey, message, severity = "Yellow" } = req.body || {};
    if (!materialKey || !message) {
      return res.status(400).json({ ok: false, message: "materialKey and message are required" });
    }

    const alert = await Alert.create({
      materialKey,
      message,
      severity,
      createdBy: req.user.username,
      cleared: false,
    });

    res.status(201).json({ ok: true, alert });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.patch("/api/alerts/:id/clear", auth, allowRoles("admin", "owner"), async (req, res) => {
  try {
    const { id } = req.params;
    const alert = await Alert.findById(id);
    if (!alert) return res.status(404).json({ ok: false, message: "Alert not found" });

    alert.cleared = true;
    alert.clearedAt = new Date();
    alert.clearedBy = req.user.username;
    await alert.save();

    res.json({ ok: true, alert });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

/* -------------------------
 * Supplier routes
 * ------------------------- */
app.get("/api/supplier-deliveries", auth, allowRoles("owner", "admin"), async (_req, res) => {
  try {
    const deliveries = await SupplierDelivery.find().sort({ createdAt: -1 }).limit(500);
    res.json({ ok: true, deliveries });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/api/supplier-deliveries", auth, allowRoles("owner", "admin"), async (req, res) => {
  try {
    const { supplier, item, qty, cost } = req.body || {};
    const nQty = Number(qty);
    const nCost = Number(cost);

    if (
      !supplier ||
      !item ||
      !Number.isFinite(nQty) ||
      nQty <= 0 ||
      !Number.isFinite(nCost) ||
      nCost <= 0
    ) {
      return res.status(400).json({ ok: false, message: "supplier, item, qty, cost are required" });
    }

    const delivery = await SupplierDelivery.create({
      supplier,
      item,
      qty: nQty,
      cost: nCost,
      createdBy: req.user.username,
      createdAt: new Date(),
    });

    res.status(201).json({ ok: true, delivery });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

/* -------------------------
 * Owner dashboard summary
 * ------------------------- */
app.get("/api/dashboard/owner", auth, allowRoles("owner"), async (_req, res) => {
  try {
    const orders = await Order.find();
    const deliveries = await SupplierDelivery.find();

    const totalSales = orders.reduce((s, o) => s + Number(o.revenue || 0), 0);
    const totalCogs = orders.reduce((s, o) => s + Number(o.cogs || 0), 0);
    const totalSupplierExpense = deliveries.reduce((s, d) => s + Number(d.cost || 0), 0);

    res.json({
      ok: true,
      totals: {
        totalSales,
        totalCogs,
        totalSupplierExpense,
        grossProfit: totalSales - totalCogs,
        netAfterSupplier: totalSales - totalSupplierExpense,
      },
      counts: {
        orders: orders.length,
        deliveries: deliveries.length,
      },
    });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

/* -------------------------
 * Start
 * ------------------------- */
async function startServer() {
  try {
    if (!process.env.MONGO_URI) throw new Error("MONGO_URI is missing");

    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      connectTimeoutMS: 10000,
      maxPoolSize: 10,
    });

    await ensureSeedData();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on ${PORT}`);
    });
  } catch (err) {
    console.error("Startup error:", err.message);
    process.exit(1);
  }
}

process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
});

startServer();
