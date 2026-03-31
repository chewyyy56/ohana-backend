const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET || "supersecretkey";

const PRODUCTS = [
  { id: 1, name: "Americano", category: "Coffee", prices: { "12oz": 60, "16oz": 70, "22oz": 80 } },
  { id: 2, name: "Cafe Latte", category: "Coffee", prices: { "12oz": 80, "16oz": 90, "22oz": 100 } },
  { id: 3, name: "Caramel Latte", category: "Coffee", prices: { "12oz": 90, "16oz": 100, "22oz": 110 } },
  { id: 4, name: "Hazelnut Latte", category: "Coffee", prices: { "12oz": 90, "16oz": 100, "22oz": 110 } },
  { id: 5, name: "Spanish Latte", category: "Coffee", prices: { "12oz": 90, "16oz": 100, "22oz": 110 } },
  { id: 6, name: "Vanilla Latte", category: "Coffee", prices: { "12oz": 95, "16oz": 105, "22oz": 115 } },
  { id: 7, name: "Dark Mocha", category: "Coffee", prices: { "12oz": 95, "16oz": 105, "22oz": 115 } },
  { id: 8, name: "White Mocha", category: "Coffee", prices: { "12oz": 95, "16oz": 105, "22oz": 115 } },
  { id: 9, name: "Caramel Macchiato", category: "Coffee", prices: { "12oz": 95, "16oz": 105, "22oz": 115 } },
  { id: 10, name: "Dirty Matcha Latte", category: "Coffee", prices: { "12oz": 95, "16oz": 105, "22oz": 115 } },
  { id: 11, name: "Matcha Latte", category: "Non-Coffee", prices: { "12oz": 85, "16oz": 95, "22oz": 105 } },
  { id: 12, name: "Double Chocolate", category: "Non-Coffee", prices: { "12oz": 85, "16oz": 95, "22oz": 105 } },
  { id: 13, name: "Espresso Shot", category: "Add-Ons", prices: { Single: 20 } },
  { id: 14, name: "Extra Milk", category: "Add-Ons", prices: { Portion: 20 } },
  { id: 15, name: "Syrup", category: "Add-Ons", prices: { Pump: 10 } },
  { id: 16, name: "Sauce", category: "Add-Ons", prices: { Drizzle: 10 } },
];

const RECIPES = {
  1: { beans: 18 },
  2: { beans: 18, milk: 200, sugarSyrup: 20 },
  3: { beans: 18, milk: 200, sugarSyrup: 40 },
  4: { beans: 18, milk: 200, sugarSyrup: 35 },
  5: { beans: 18, milk: 150, condensedMilk: 80, sugarSyrup: 30 },
  6: { beans: 18, milk: 200, sugarSyrup: 30 },
  7: { beans: 18, milk: 200, cocoaPowder: 20, sugarSyrup: 30 },
  8: { beans: 18, milk: 200, sugarSyrup: 30 },
  9: { beans: 18, milk: 180, sugarSyrup: 45 },
  10: { beans: 18, milk: 150, matchaPowder: 10, sugarSyrup: 25 },
  11: { milk: 250, matchaPowder: 15, sugarSyrup: 35 },
  12: { milk: 250, cocoaPowder: 25, sugarSyrup: 35 },
  13: { beans: 18 },
  14: { milk: 50 },
  15: { sugarSyrup: 30 },
  16: { cocoaPowder: 15 },
};

const UNIT_COST = {
  coffeeBeans: 0.02,
  matchaPowder: 0.05,
  cocoaPowder: 0.04,
  milk: 0.01,
  sugarSyrup: 0.015,
  condensedMilk: 0.03,
  cups12oz: 0.5,
  cups16oz: 0.6,
  cups22oz: 0.7,
  lids: 0.1,
  straws: 0.1,
};

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

const invKeyFor = (recipeKey) => {
  if (recipeKey === "beans") return "coffeeBeans";
  if (recipeKey === "milk") return "milk";
  if (recipeKey === "matchaPowder") return "matchaPowder";
  if (recipeKey === "cocoaPowder") return "cocoaPowder";
  if (recipeKey === "sugarSyrup") return "sugarSyrup";
  if (recipeKey === "condensedMilk") return "condensedMilk";
  return null;
};

const getSizeMultiplier = (sizeKey, isAddon) => {
  if (isAddon) return 1;
  if (sizeKey === "16oz") return 1.2;
  if (sizeKey === "22oz") return 1.5;
  return 1;
};

const computeNeeded = (product, sizeKey) => {
  const isAddon = product.category === "Add-Ons";
  const mult = getSizeMultiplier(sizeKey, isAddon);
  const base = RECIPES[product.id];
  if (!base) return null;

  const needed = {};
  for (const [k, v] of Object.entries(base)) {
    const invKey = invKeyFor(k);
    if (!invKey) continue;
    needed[invKey] = (needed[invKey] || 0) + v * mult;
  }

  if (!isAddon) {
    needed.lids = 1;
    needed.straws = 1;
    if (sizeKey === "12oz") needed.cups12oz = 1;
    if (sizeKey === "16oz") needed.cups16oz = 1;
    if (sizeKey === "22oz") needed.cups22oz = 1;
  }

  return needed;
};

const computeCogs = (needed) => {
  let total = 0;
  for (const [k, amt] of Object.entries(needed)) total += (UNIT_COST[k] || 0) * amt;
  return total;
};

const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ["owner", "admin", "staff"], required: true },
  },
  { timestamps: true }
);

const inventorySchema = new mongoose.Schema(
  {
    items: { type: Map, of: Number, default: {} },
  },
  { timestamps: true }
);

const orderSchema = new mongoose.Schema(
  {
    productId: Number,
    productName: String,
    size: String,
    revenue: Number,
    cogs: Number,
    createdBy: String,
  },
  { timestamps: true }
);

const alertSchema = new mongoose.Schema(
  {
    materialKey: String,
    message: String,
    severity: { type: String, enum: ["Red", "Yellow"], default: "Yellow" },
    status: { type: String, enum: ["open", "cleared"], default: "open" },
    createdBy: String,
  },
  { timestamps: true }
);

const supplierDeliverySchema = new mongoose.Schema(
  {
    supplier: String,
    item: String,
    qty: Number,
    cost: Number,
    createdBy: String,
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Inventory = mongoose.model("Inventory", inventorySchema);
const Order = mongoose.model("Order", orderSchema);
const Alert = mongoose.model("Alert", alertSchema);
const SupplierDelivery = mongoose.model("SupplierDelivery", supplierDeliverySchema);

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

const allowRoles = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role)) return res.status(403).json({ message: "Forbidden" });
  return next();
};

async function ensureSeedData() {
  const usersCount = await User.countDocuments();
  if (usersCount === 0) {
    const ownerHash = await bcrypt.hash("1234", 10);
    const adminHash = await bcrypt.hash("1234", 10);
    const staffHash = await bcrypt.hash("1234", 10);

    await User.insertMany([
      { username: "owner", passwordHash: ownerHash, role: "owner" },
      { username: "admin", passwordHash: adminHash, role: "admin" },
      { username: "staff", passwordHash: staffHash, role: "staff" },
    ]);
  }

  const inv = await Inventory.findOne();
  if (!inv) await Inventory.create({ items: INITIAL_INVENTORY });
}

app.get("/", (req, res) => {
  res.json({ ok: true });
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, mongoState: mongoose.connection.readyState });
});

app.get("/api/products", (req, res) => {
  res.json(PRODUCTS);
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(String(password || ""), user.passwordHash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "12h" }
    );

    return res.json({ token, user: { username: user.username, role: user.role } });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.get("/api/inventory", auth, async (req, res) => {
  const inv = await Inventory.findOne();
  res.json(inv?.items || {});
});

app.patch("/api/inventory/restock", auth, allowRoles("admin", "owner"), async (req, res) => {
  try {
    const { materialKey, qty } = req.body || {};
    const amount = Number(qty);
    if (!materialKey || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ message: "Invalid materialKey or qty" });
    }

    const inv = await Inventory.findOne();
    if (!inv) return res.status(404).json({ message: "Inventory not found" });

    const current = Number(inv.items.get(materialKey) || 0);
    inv.items.set(materialKey, current + amount);
    await inv.save();

    return res.json({ ok: true, materialKey, newQty: inv.items.get(materialKey) });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.post("/api/alerts", auth, allowRoles("staff"), async (req, res) => {
  try {
    const { materialKey, message, severity } = req.body || {};
    if (!materialKey || !message) {
      return res.status(400).json({ message: "materialKey and message are required" });
    }

    const existing = await Alert.findOne({ materialKey, status: "open" });
    if (existing) return res.json({ ok: true, duplicate: true, alert: existing });

    const alert = await Alert.create({
      materialKey,
      message,
      severity: severity || "Yellow",
      createdBy: req.user.username,
    });

    return res.status(201).json({ ok: true, alert });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.get("/api/alerts", auth, allowRoles("admin", "owner"), async (req, res) => {
  const alerts = await Alert.find({ status: "open" }).sort({ createdAt: -1 });
  res.json(alerts);
});

app.patch("/api/alerts/:id/clear", auth, allowRoles("admin", "owner"), async (req, res) => {
  const alert = await Alert.findByIdAndUpdate(req.params.id, { status: "cleared" }, { new: true });
  if (!alert) return res.status(404).json({ message: "Alert not found" });
  res.json({ ok: true, alert });
});

app.post("/api/orders", auth, async (req, res) => {
  try {
    const { productId, size } = req.body || {};
    const product = PRODUCTS.find((p) => p.id === Number(productId));
    if (!product) return res.status(404).json({ message: "Product not found" });

    const sizeKey = size || Object.keys(product.prices)[0];
    const price = Number(product.prices[sizeKey] || 0);
    if (!price) return res.status(400).json({ message: "Invalid size/price" });

    const needed = computeNeeded(product, sizeKey);
    if (!needed) return res.status(400).json({ message: "Recipe not found" });

    const inv = await Inventory.findOne();
    if (!inv) return res.status(404).json({ message: "Inventory not found" });

    for (const [k, amt] of Object.entries(needed)) {
      const onHand = Number(inv.items.get(k) || 0);
      if (onHand < amt) return res.status(400).json({ message: `Not enough ${k}` });
    }

    for (const [k, amt] of Object.entries(needed)) {
      const onHand = Number(inv.items.get(k) || 0);
      inv.items.set(k, onHand - amt);
    }
    await inv.save();

    const cogs = computeCogs(needed);

    const order = await Order.create({
      productId: product.id,
      productName: product.name,
      size: sizeKey,
      revenue: price,
      cogs,
      createdBy: req.user.username,
    });

    return res.status(201).json({ ok: true, order, updatedInventory: inv.items });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.get("/api/orders", auth, async (req, res) => {
  const orders = await Order.find().sort({ createdAt: -1 }).limit(300);
  res.json(orders);
});

app.post("/api/supplier-deliveries", auth, allowRoles("admin", "owner"), async (req, res) => {
  try {
    const { supplier, item, qty, cost } = req.body || {};
    const qtyNum = Number(qty);
    const costNum = Number(cost);

    if (!supplier || !item || qtyNum <= 0 || costNum <= 0) {
      return res.status(400).json({ message: "supplier, item, qty, cost are required" });
    }

    const delivery = await SupplierDelivery.create({
      supplier,
      item,
      qty: qtyNum,
      cost: costNum,
      createdBy: req.user.username,
    });

    return res.status(201).json({ ok: true, delivery });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

app.get("/api/supplier-deliveries", auth, allowRoles("admin", "owner"), async (req, res) => {
  const deliveries = await SupplierDelivery.find().sort({ createdAt: -1 }).limit(200);
  res.json(deliveries);
});

app.get("/api/dashboard/owner", auth, allowRoles("owner"), async (req, res) => {
  const [orders, deliveries] = await Promise.all([Order.find(), SupplierDelivery.find()]);

  const totalSales = orders.reduce((s, o) => s + (o.revenue || 0), 0);
  const totalCogs = orders.reduce((s, o) => s + (o.cogs || 0), 0);
  const totalExpenses = deliveries.reduce((s, d) => s + (d.cost || 0), 0);
  const netProfit = totalSales - totalExpenses;

  const topMap = {};
  const hourMap = {};
  for (let h = 0; h < 24; h++) hourMap[h] = 0;

  for (const o of orders) {
    topMap[o.productName] = (topMap[o.productName] || 0) + 1;
    const h = new Date(o.createdAt).getHours();
    hourMap[h] += 1;
  }

  const topProducts = Object.entries(topMap)
    .map(([name, units]) => ({ name, units }))
    .sort((a, b) => b.units - a.units)
    .slice(0, 5);

  const peakHours = Object.entries(hourMap).map(([hour, count]) => ({
    hour: Number(hour),
    orders: count,
  }));

  res.json({
    totalSales,
    totalCogs,
    totalExpenses,
    grossMarginPercent: totalSales ? ((totalSales - totalCogs) / totalSales) * 100 : 0,
    netProfit,
    topProducts,
    peakHours,
  });
});

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

startServer();
