const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "";
const VALID_ROLES = ["owner", "admin", "staff"];

/* -------------------------
 * Simple in-memory rate limiter
 * ------------------------- */
function makeRateLimiter({ windowMs, max }) {
  const store = new Map();

  return (req, res, next) => {
    const now = Date.now();
    const key = `${req.ip}:${req.path}`;
    const prev = store.get(key);

    if (!prev || now - prev.start > windowMs) {
      store.set(key, { count: 1, start: now });
      return next();
    }

    prev.count += 1;
    if (prev.count > max) {
      return res.status(429).json({ ok: false, message: "Too many requests. Please try again later." });
    }

    return next();
  };
}

const loginLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 30 });
const registerLimiter = makeRateLimiter({ windowMs: 60 * 60 * 1000, max: 15 });

/* -------------------------
 * Schemas
 * ------------------------- */
const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, required: true, lowercase: true, trim: true },
    email: { type: String, default: "", trim: true, lowercase: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: VALID_ROLES, default: "staff" },
    active: { type: Boolean, default: true },
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
    groupId: { type: String, index: true, default: "" },
    createdAt: { type: Date, default: Date.now },
    productId: Number,
    productName: String,
    size: String,
    quantity: { type: Number, default: 1 },
    revenue: { type: Number, default: 0 }, // total line revenue
    cogs: { type: Number, default: 0 }, // total line cogs
    needed: { type: mongoose.Schema.Types.Mixed, default: {} }, // total deducted materials for line
    orderedBy: { type: String, default: "" },

    status: { type: String, enum: ["active", "canceled"], default: "active" },
    cancelReason: { type: String, default: "" },
    canceledAt: { type: Date, default: null },
    canceledBy: { type: String, default: "" },
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

const auditLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  actor: { type: String, default: "" },
  actorRole: { type: String, default: "" },
  target: { type: String, default: "" },
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", userSchema);
const Inventory = mongoose.model("Inventory", inventorySchema);
const Order = mongoose.model("Order", orderSchema);
const Alert = mongoose.model("Alert", alertSchema);
const SupplierDelivery = mongoose.model("SupplierDelivery", supplierDeliverySchema);
const AuditLog = mongoose.model("AuditLog", auditLogSchema);

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
 * Helpers
 * ------------------------- */
function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

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
  } catch (_err) {
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

function manageableRolesFor(role) {
  if (role === "owner") return ["admin", "staff"];
  if (role === "admin") return ["staff"];
  return [];
}

function publicUser(user) {
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    role: user.role,
    active: user.active !== false,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

function toHttpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

function makeGroupId() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  const rand = Math.random().toString(36).slice(2, 8).toUpperCase();
  return `ORD-${y}${m}${d}-${rand}`;
}

function scaleNeeded(neededPerUnit, quantity) {
  const out = {};
  for (const [k, amt] of Object.entries(neededPerUnit || {})) {
    const n = Number(amt || 0) * Number(quantity || 0);
    if (n > 0) out[k] = n;
  }
  return out;
}

function normalizeOrderItem(raw) {
  const productId = Number(raw?.productId);
  const productName = String(raw?.productName || "").trim();
  const size = String(raw?.size || "").trim();
  const quantity = Math.floor(Number(raw?.quantity ?? raw?.qty ?? 1));
  const revenueUnit = Number(raw?.revenue ?? 0);
  const cogsUnit = Number(raw?.cogs ?? 0);
  const neededPerUnit = raw?.neededPerUnit || raw?.needed || {};

  if (!Number.isFinite(productId)) return null;
  if (!productName || !size) return null;
  if (!Number.isFinite(quantity) || quantity <= 0) return null;
  if (!Number.isFinite(revenueUnit) || revenueUnit < 0) return null;
  if (!Number.isFinite(cogsUnit) || cogsUnit < 0) return null;
  if (typeof neededPerUnit !== "object" || Array.isArray(neededPerUnit)) return null;

  return {
    productId,
    productName,
    size,
    quantity,
    revenueUnit,
    cogsUnit,
    neededPerUnit,
  };
}

function getBootstrapUsersFromEnv() {
  return [
    {
      username: process.env.SEED_OWNER_USERNAME,
      password: process.env.SEED_OWNER_PASSWORD,
      email: process.env.SEED_OWNER_EMAIL || "",
      role: "owner",
    },
    {
      username: process.env.SEED_ADMIN_USERNAME,
      password: process.env.SEED_ADMIN_PASSWORD,
      email: process.env.SEED_ADMIN_EMAIL || "",
      role: "admin",
    },
    {
      username: process.env.SEED_STAFF_USERNAME,
      password: process.env.SEED_STAFF_PASSWORD,
      email: process.env.SEED_STAFF_EMAIL || "",
      role: "staff",
    },
  ];
}

/* -------------------------
 * Seed data
 * ------------------------- */
async function ensureSeedData() {
  const inv = await Inventory.findOne();
  if (!inv) {
    await Inventory.create({ items: { ...INITIAL_INVENTORY } });
  }

  const seedUsers = getBootstrapUsersFromEnv();

  for (const u of seedUsers) {
    const uname = normalizeUsername(u.username);
    const pass = String(u.password || "");
    if (!uname || !pass) continue;

    const exists = await User.findOne({ username: uname });
    if (exists) continue;

    const passwordHash = await bcrypt.hash(pass, 10);
    await User.create({
      username: uname,
      email: normalizeEmail(u.email),
      role: u.role,
      passwordHash,
    });
  }
}

/* -------------------------
 * Checkout core (transaction-safe)
 * ------------------------- */
async function checkoutCore({ lineItems, actor, actorRole, session }) {
  if (!Array.isArray(lineItems) || !lineItems.length) {
    throw toHttpError(400, "No line items.");
  }

  const normalized = [];
  const aggregateNeeded = {};
  let totalAmount = 0;
  let totalItems = 0;

  for (const raw of lineItems) {
    const item = normalizeOrderItem(raw);
    if (!item) throw toHttpError(400, "Invalid item in payload.");

    const neededTotal = scaleNeeded(item.neededPerUnit, item.quantity);

    for (const [k, amt] of Object.entries(neededTotal)) {
      aggregateNeeded[k] = (aggregateNeeded[k] || 0) + amt;
    }

    totalAmount += item.revenueUnit * item.quantity;
    totalItems += item.quantity;

    normalized.push({ ...item, neededTotal });
  }

  const invDoc = await Inventory.findOne().session(session);
  if (!invDoc) throw toHttpError(404, "Inventory not found");

  for (const [k, required] of Object.entries(aggregateNeeded)) {
    const onHand = Number(invDoc.items[k] || 0);
    if (onHand < required) {
      throw toHttpError(400, `Not enough ${k}`);
    }
  }

  const filter = { _id: invDoc._id };
  const incMap = {};

  for (const [k, required] of Object.entries(aggregateNeeded)) {
    filter[`items.${k}`] = { $gte: required };
    incMap[`items.${k}`] = -required;
  }

  const updatedInventory =
    Object.keys(incMap).length > 0
      ? await Inventory.findOneAndUpdate(filter, { $inc: incMap }, { new: true, session })
      : invDoc;

  if (!updatedInventory) {
    throw toHttpError(409, "Stock changed while checking out. Please retry.");
  }

  const groupId = makeGroupId();
  const now = new Date();

  const docs = normalized.map((item) => ({
    groupId,
    createdAt: now,
    productId: item.productId,
    productName: item.productName,
    size: item.size,
    quantity: item.quantity,
    revenue: item.revenueUnit * item.quantity,
    cogs: item.cogsUnit * item.quantity,
    needed: item.neededTotal,
    orderedBy: actor,
    status: "active",
  }));

  const createdOrders = await Order.insertMany(docs, { session });

  const groupSummary = {
    groupId,
    status: "active",
    orderedBy: actor,
    createdAt: now,
    totalItems,
    totalAmount,
    items: createdOrders.map((o) => ({
      id: o._id,
      productId: o.productId,
      productName: o.productName,
      size: o.size,
      quantity: o.quantity,
      revenue: o.revenue,
      cogs: o.cogs,
      status: o.status,
    })),
  };

  await AuditLog.create(
    [
      {
        action: "checkout_group",
        actor,
        actorRole,
        target: groupId,
        details: {
          lines: createdOrders.length,
          totalItems,
          totalAmount,
        },
        createdAt: now,
      },
    ],
    { session }
  );

  return { updatedInventory, createdOrders, groupSummary };
}

/* -------------------------
 * Basic routes
 * ------------------------- */
app.get("/", (_req, res) => {
  res.json({ ok: true, service: "ohana-backend" });
});

app.get("/api/health", (_req, res) => {
  const mongoState = mongoose.connection.readyState;
  res.json({ ok: true, mongoState });
});

/* -------------------------
 * Auth routes
 * ------------------------- */
app.post("/api/auth/register", registerLimiter, async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if (!username || !email || !password) {
      return res.status(400).json({ ok: false, message: "Username, email, and password are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ ok: false, message: "Password must be at least 6 characters" });
    }

    const usernameTaken = await User.findOne({ username });
    if (usernameTaken) return res.status(409).json({ ok: false, message: "Username already exists" });

    const emailTaken = await User.findOne({ email });
    if (emailTaken) return res.status(409).json({ ok: false, message: "Email already exists" });

    const user = await User.create({
      username,
      email,
      role: "staff",
      passwordHash: await bcrypt.hash(password, 10),
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

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const password = String(req.body?.password || "");

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ ok: false, message: "Invalid username or password" });
    if (user.active === false) {
      return res.status(401).json({ ok: false, message: "This account is no longer active" });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
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
 * Staff account management
 * ------------------------- */
app.get("/api/users", auth, allowRoles("admin", "owner"), async (req, res) => {
  try {
    const roles = manageableRolesFor(req.user.role);
    const users = await User.find({ role: { $in: roles } }).sort({ role: 1, username: 1 });
    res.json({ ok: true, users: users.map(publicUser) });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.post("/api/users", auth, allowRoles("admin", "owner"), async (req, res) => {
  try {
    const roles = manageableRolesFor(req.user.role);
    const username = normalizeUsername(req.body?.username);
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");
    const role = String(req.body?.role || "staff");

    if (!roles.includes(role)) {
      return res.status(403).json({ ok: false, message: "You cannot create that account role" });
    }
    if (!username || !password) {
      return res.status(400).json({ ok: false, message: "Username and password are required" });
    }
    if (password.length < 6) {
      return res.status(400).json({ ok: false, message: "Password must be at least 6 characters" });
    }

    const usernameTaken = await User.findOne({ username });
    if (usernameTaken) return res.status(409).json({ ok: false, message: "Username already exists" });

    if (email) {
      const emailTaken = await User.findOne({ email });
      if (emailTaken) return res.status(409).json({ ok: false, message: "Email already exists" });
    }

    const user = await User.create({
      username,
      email,
      role,
      active: true,
      passwordHash: await bcrypt.hash(password, 10),
    });

    await AuditLog.create({
      action: "create_user",
      actor: req.user.username,
      actorRole: req.user.role,
      target: user.username,
      details: { role: user.role },
      createdAt: new Date(),
    });

    res.status(201).json({ ok: true, user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.patch("/api/users/:id", auth, allowRoles("admin", "owner"), async (req, res) => {
  try {
    const roles = manageableRolesFor(req.user.role);
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ ok: false, message: "User not found" });
    if (!roles.includes(user.role)) {
      return res.status(403).json({ ok: false, message: "You cannot edit that account" });
    }

    const nextRole = req.body?.role ? String(req.body.role) : user.role;
    if (!roles.includes(nextRole)) {
      return res.status(403).json({ ok: false, message: "You cannot assign that account role" });
    }

    const nextUsername = req.body?.username !== undefined ? normalizeUsername(req.body.username) : user.username;
    const nextEmail = req.body?.email !== undefined ? normalizeEmail(req.body.email) : user.email;
    const nextPassword = String(req.body?.password || "");

    if (!nextUsername) {
      return res.status(400).json({ ok: false, message: "Username is required" });
    }

    const usernameTaken = await User.findOne({ username: nextUsername, _id: { $ne: user._id } });
    if (usernameTaken) return res.status(409).json({ ok: false, message: "Username already exists" });

    if (nextEmail) {
      const emailTaken = await User.findOne({ email: nextEmail, _id: { $ne: user._id } });
      if (emailTaken) return res.status(409).json({ ok: false, message: "Email already exists" });
    }

    if (nextPassword) {
      if (nextPassword.length < 6) {
        return res.status(400).json({ ok: false, message: "Password must be at least 6 characters" });
      }
      user.passwordHash = await bcrypt.hash(nextPassword, 10);
    }

    user.username = nextUsername;
    user.email = nextEmail;
    user.role = nextRole;
    if (req.body?.active !== undefined) user.active = Boolean(req.body.active);
    await user.save();

    await AuditLog.create({
      action: "update_user",
      actor: req.user.username,
      actorRole: req.user.role,
      target: user.username,
      details: { role: user.role, active: user.active !== false },
      createdAt: new Date(),
    });

    res.json({ ok: true, user: publicUser(user) });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.delete("/api/users/:id", auth, allowRoles("admin", "owner"), async (req, res) => {
  try {
    const roles = manageableRolesFor(req.user.role);
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ ok: false, message: "User not found" });
    if (!roles.includes(user.role)) {
      return res.status(403).json({ ok: false, message: "You cannot delete that account" });
    }
    if (String(user._id) === String(req.user.id)) {
      return res.status(400).json({ ok: false, message: "You cannot delete your own account" });
    }

    await User.deleteOne({ _id: user._id });

    await AuditLog.create({
      action: "delete_user",
      actor: req.user.username,
      actorRole: req.user.role,
      target: user.username,
      details: { role: user.role },
      createdAt: new Date(),
    });

    res.json({ ok: true, message: "Account deleted", user: publicUser(user) });
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
    const materialKey = String(req.body?.materialKey || "");
    const qty = Number(req.body?.qty);

    if (!materialKey || !Number.isFinite(qty) || qty <= 0) {
      return res.status(400).json({ ok: false, message: "materialKey and positive qty are required" });
    }

    const inv = await Inventory.findOne();
    if (!inv) return res.status(404).json({ ok: false, message: "Inventory not found" });

    inv.items[materialKey] = Number(inv.items[materialKey] || 0) + qty;
    inv.markModified("items");
    await inv.save();

    await AuditLog.create({
      action: "restock_material",
      actor: req.user.username,
      actorRole: req.user.role,
      target: materialKey,
      details: { qty },
      createdAt: new Date(),
    });

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

// staff-facing grouped orders
app.get("/api/orders/staff", auth, allowRoles("staff", "admin", "owner"), async (req, res) => {
  try {
    const includeCanceled = String(req.query.includeCanceled || "") === "true";
    const filter = { groupId: { $ne: "" } };

    if (req.user.role === "staff") {
      filter.orderedBy = req.user.username;
    } else if (req.query.username) {
      filter.orderedBy = normalizeUsername(req.query.username);
    }

    if (!includeCanceled) {
      filter.status = "active";
    }

    const docs = await Order.find(filter)
      .sort({ createdAt: -1 })
      .limit(1500);

    const map = new Map();

    for (const o of docs) {
      const gid = o.groupId || String(o._id);

      if (!map.has(gid)) {
        map.set(gid, {
          groupId: gid,
          createdAt: o.createdAt,
          orderedBy: o.orderedBy,
          status: o.status,
          totalItems: 0,
          totalAmount: 0,
          items: [],
          canceledAt: o.canceledAt || null,
          canceledBy: o.canceledBy || "",
          cancelReason: o.cancelReason || "",
        });
      }

      const g = map.get(gid);
      g.totalItems += Number(o.quantity || 1);
      g.totalAmount += Number(o.revenue || 0);
      if (o.status === "active") g.status = "active";
      if (o.status === "canceled" && g.status !== "active") g.status = "canceled";
      if (o.canceledAt && !g.canceledAt) g.canceledAt = o.canceledAt;
      if (o.canceledBy && !g.canceledBy) g.canceledBy = o.canceledBy;
      if (o.cancelReason && !g.cancelReason) g.cancelReason = o.cancelReason;

      g.items.push({
        id: o._id,
        productId: o.productId,
        productName: o.productName,
        size: o.size,
        quantity: o.quantity,
        revenue: o.revenue,
        cogs: o.cogs,
        status: o.status,
      });
    }

    const groups = Array.from(map.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ ok: true, groups: groups.slice(0, 50) });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

// single-line legacy checkout (compat)
app.post("/api/orders", auth, async (req, res) => {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();

    const item = normalizeOrderItem(req.body || {});
    if (!item) throw toHttpError(400, "Invalid order payload");

    const { updatedInventory, createdOrders, groupSummary } = await checkoutCore({
      lineItems: [item],
      actor: req.user.username,
      actorRole: req.user.role,
      session,
    });

    await session.commitTransaction();

    res.status(201).json({
      ok: true,
      order: createdOrders[0],
      group: groupSummary,
      inventory: updatedInventory.items,
    });
  } catch (err) {
    await session.abortTransaction();
    res.status(err.status || 500).json({ ok: false, message: err.message });
  } finally {
    session.endSession();
  }
});

// multi-line checkout
app.post("/api/orders/checkout", auth, async (req, res) => {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();

    const lineItems = Array.isArray(req.body?.items) ? req.body.items : [];
    const { updatedInventory, createdOrders, groupSummary } = await checkoutCore({
      lineItems,
      actor: req.user.username,
      actorRole: req.user.role,
      session,
    });

    await session.commitTransaction();

    res.status(201).json({
      ok: true,
      group: groupSummary,
      orders: createdOrders,
      inventory: updatedInventory.items,
    });
  } catch (err) {
    await session.abortTransaction();
    res.status(err.status || 500).json({ ok: false, message: err.message });
  } finally {
    session.endSession();
  }
});

// cancel order group (staff own group, admin/owner any group)
app.patch("/api/orders/group/:groupId/cancel", auth, allowRoles("staff", "admin", "owner"), async (req, res) => {
  const session = await mongoose.startSession();
  try {
    session.startTransaction();

    const groupId = String(req.params.groupId || "").trim();
    const reason = String(req.body?.reason || "Customer changed mind").trim();

    if (!groupId) throw toHttpError(400, "groupId is required");

    const activeOrders = await Order.find({ groupId, status: "active" }).session(session);
    if (!activeOrders.length) throw toHttpError(404, "No active orders found for this group");

    const orderedBy = activeOrders[0].orderedBy;
    const createdAt = activeOrders[0].createdAt;

    if (req.user.role === "staff") {
      if (orderedBy !== req.user.username) {
        throw toHttpError(403, "Staff can only cancel their own order group");
      }
    }

    const restoreMap = {};
    let totalItems = 0;
    let totalAmount = 0;

    for (const o of activeOrders) {
      totalItems += Number(o.quantity || 1);
      totalAmount += Number(o.revenue || 0);
      for (const [k, v] of Object.entries(o.needed || {})) {
        restoreMap[k] = (restoreMap[k] || 0) + Number(v || 0);
      }
    }

    const invDoc = await Inventory.findOne().session(session);
    if (!invDoc) throw toHttpError(404, "Inventory not found");

    const incMap = {};
    for (const [k, v] of Object.entries(restoreMap)) {
      if (v > 0) incMap[`items.${k}`] = v;
    }

    const updatedInventory =
      Object.keys(incMap).length > 0
        ? await Inventory.findOneAndUpdate({ _id: invDoc._id }, { $inc: incMap }, { new: true, session })
        : invDoc;

    await Order.updateMany(
      { groupId, status: "active" },
      {
        $set: {
          status: "canceled",
          canceledAt: new Date(),
          canceledBy: req.user.username,
          cancelReason: reason,
        },
      },
      { session }
    );

    const finalOrders = await Order.find({ groupId }).session(session);

    const group = {
      groupId,
      createdAt,
      orderedBy,
      status: "canceled",
      totalItems,
      totalAmount,
      canceledAt: new Date(),
      canceledBy: req.user.username,
      cancelReason: reason,
      items: finalOrders.map((o) => ({
        id: o._id,
        productId: o.productId,
        productName: o.productName,
        size: o.size,
        quantity: o.quantity,
        revenue: o.revenue,
        cogs: o.cogs,
        status: o.status,
      })),
    };

    await AuditLog.create(
      [
        {
          action: "cancel_group",
          actor: req.user.username,
          actorRole: req.user.role,
          target: groupId,
          details: {
            reason,
            totalItems,
            totalAmount,
          },
          createdAt: new Date(),
        },
      ],
      { session }
    );

    await session.commitTransaction();

    res.json({
      ok: true,
      message: "Order group canceled.",
      group,
      inventory: updatedInventory.items,
    });
  } catch (err) {
    await session.abortTransaction();
    res.status(err.status || 500).json({ ok: false, message: err.message });
  } finally {
    session.endSession();
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
    const materialKey = String(req.body?.materialKey || "");
    const message = String(req.body?.message || "");
    const severity = String(req.body?.severity || "Yellow");

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
    const alert = await Alert.findById(req.params.id);
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
    const supplier = String(req.body?.supplier || "").trim();
    const item = String(req.body?.item || "").trim();
    const qty = Number(req.body?.qty);
    const cost = Number(req.body?.cost);

    if (!supplier || !item || !Number.isFinite(qty) || qty <= 0 || !Number.isFinite(cost) || cost <= 0) {
      return res.status(400).json({ ok: false, message: "supplier, item, qty, cost are required" });
    }

    const delivery = await SupplierDelivery.create({
      supplier,
      item,
      qty,
      cost,
      createdBy: req.user.username,
      createdAt: new Date(),
    });

    await AuditLog.create({
      action: "add_supplier_delivery",
      actor: req.user.username,
      actorRole: req.user.role,
      target: delivery._id.toString(),
      details: { supplier, item, qty, cost },
      createdAt: new Date(),
    });

    res.status(201).json({ ok: true, delivery });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

/* -------------------------
 * Audit + Owner dashboard
 * ------------------------- */
app.get("/api/audit-logs", auth, allowRoles("owner"), async (_req, res) => {
  try {
    const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(300);
    res.json({ ok: true, logs });
  } catch (err) {
    res.status(500).json({ ok: false, message: err.message });
  }
});

app.get("/api/dashboard/owner", auth, allowRoles("owner"), async (_req, res) => {
  try {
    const orders = await Order.find({ status: "active" });
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
    if (!JWT_SECRET || JWT_SECRET.length < 16) {
      throw new Error("JWT_SECRET must be set and at least 16 characters");
    }

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
