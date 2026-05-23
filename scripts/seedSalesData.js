const mongoose = require("mongoose");
require("dotenv").config();

const ORDER_STATUSES = ["active", "processing", "ready", "completed", "canceled"];

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
    revenue: { type: Number, default: 0 },
    cogs: { type: Number, default: 0 },
    needed: { type: mongoose.Schema.Types.Mixed, default: {} },
    orderedBy: { type: String, default: "" },
    status: { type: String, enum: ORDER_STATUSES, default: "completed" },
    cancelReason: { type: String, default: "" },
    canceledAt: { type: Date, default: null },
    canceledBy: { type: String, default: "" },
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

const alertSchema = new mongoose.Schema({}, { strict: false });

const Inventory = mongoose.model("Inventory", inventorySchema);
const Order = mongoose.model("Order", orderSchema);
const SupplierDelivery = mongoose.model("SupplierDelivery", supplierDeliverySchema);
const Alert = mongoose.model("Alert", alertSchema);

const PRODUCTS = [
  { id: 1, name: "Americano", prices: { "12oz": 60, "16oz": 70, "22oz": 80 }, weight: 11, cogsRate: 0.36 },
  { id: 2, name: "Cafe Latte", prices: { "12oz": 80, "16oz": 90, "22oz": 100 }, weight: 13, cogsRate: 0.42 },
  { id: 3, name: "Caramel Latte", prices: { "12oz": 90, "16oz": 100, "22oz": 110 }, weight: 14, cogsRate: 0.44 },
  { id: 4, name: "Hazelnut Latte", prices: { "12oz": 90, "16oz": 100, "22oz": 110 }, weight: 10, cogsRate: 0.44 },
  { id: 5, name: "Mocha", prices: { "12oz": 90, "16oz": 100, "22oz": 110 }, weight: 11, cogsRate: 0.45 },
  { id: 6, name: "Spanish Latte", prices: { "12oz": 95, "16oz": 105, "22oz": 115 }, weight: 13, cogsRate: 0.45 },
  { id: 7, name: "White Mocha", prices: { "12oz": 95, "16oz": 105, "22oz": 115 }, weight: 8, cogsRate: 0.46 },
  { id: 8, name: "Matcha Latte", prices: { "12oz": 95, "16oz": 105, "22oz": 115 }, weight: 9, cogsRate: 0.43 },
  { id: 9, name: "Dark Chocolate", prices: { "12oz": 95, "16oz": 105, "22oz": 115 }, weight: 7, cogsRate: 0.43 },
  { id: 10, name: "Strawberry Latte", prices: { "12oz": 95, "16oz": 105, "22oz": 115 }, weight: 7, cogsRate: 0.47 },
  { id: 11, name: "Iced Tea", prices: { "12oz": 85, "16oz": 95, "22oz": 105 }, weight: 5, cogsRate: 0.35 },
  { id: 12, name: "Lemonade", prices: { "12oz": 85, "16oz": 95, "22oz": 105 }, weight: 5, cogsRate: 0.35 },
];

const ADD_ONS = [
  { id: 13, name: "Extra Shot", size: "Single", price: 20, cogsRate: 0.35 },
  { id: 14, name: "Whipped Cream", size: "Portion", price: 20, cogsRate: 0.38 },
  { id: 15, name: "Vanilla Syrup", size: "Pump", price: 10, cogsRate: 0.3 },
  { id: 16, name: "Caramel Drizzle", size: "Drizzle", price: 10, cogsRate: 0.3 },
];

const HEALTHY_INVENTORY = {
  coffeeBeans: 28000,
  matchaPowder: 6500,
  cocoaPowder: 7500,
  milk: 52000,
  sugarSyrup: 26000,
  condensedMilk: 11000,
  cups12oz: 420,
  cups16oz: 460,
  cups22oz: 360,
  lids: 1200,
  straws: 1200,
};

function seededRandom(seed) {
  let state = seed % 2147483647;
  if (state <= 0) state += 2147483646;
  return () => {
    state = (state * 16807) % 2147483647;
    return (state - 1) / 2147483646;
  };
}

function pickWeighted(items, rand) {
  const total = items.reduce((sum, item) => sum + item.weight, 0);
  let roll = rand() * total;
  for (const item of items) {
    roll -= item.weight;
    if (roll <= 0) return item;
  }
  return items[items.length - 1];
}

function addDays(date, days) {
  const next = new Date(date);
  next.setDate(next.getDate() + days);
  return next;
}

function ymd(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}${m}${d}`;
}

function ticketCountForDay(date, rand) {
  const weekdayBase = [18, 8, 10, 11, 13, 19, 24][date.getDay()];
  const month = date.getMonth();
  const day = date.getDate();
  let multiplier = 0.85 + rand() * 0.35;

  if (date.getDay() === 5 || date.getDay() === 6) multiplier += 0.25;
  if (day === 15 || day === 30) multiplier += 0.2;
  if (month === 11 && day >= 15 && day <= 24) multiplier += 0.28;
  if (month === 11 && day === 25) multiplier = 0.35;
  if (month === 0 && day === 1) multiplier = 0.25;
  if (month === 4 && day >= 1 && day <= 12) multiplier += 0.12;

  return Math.max(3, Math.round(weekdayBase * multiplier));
}

function buildLine(product, rand) {
  const sizes = Object.keys(product.prices);
  const sizeRoll = rand();
  const size = sizes.length === 1 ? sizes[0] : sizeRoll < 0.45 ? "16oz" : sizeRoll < 0.75 ? "12oz" : "22oz";
  const quantity = rand() < 0.82 ? 1 : 2;
  const unitPrice = Number(product.prices[size]);

  return {
    productId: product.id,
    productName: product.name,
    size,
    quantity,
    revenue: unitPrice * quantity,
    cogs: Math.round(unitPrice * quantity * product.cogsRate),
    needed: {},
  };
}

function buildSeedOrders(startDate, endDate) {
  const rand = seededRandom(20260523);
  const orders = [];

  for (let cursor = new Date(startDate); cursor <= endDate; cursor = addDays(cursor, 1)) {
    const tickets = ticketCountForDay(cursor, rand);

    for (let i = 0; i < tickets; i++) {
      const groupId = `SEED-${ymd(cursor)}-${String(i + 1).padStart(3, "0")}`;
      const hour = 8 + Math.floor(rand() * 13);
      const minute = Math.floor(rand() * 60);
      const createdAt = new Date(cursor);
      createdAt.setHours(hour, minute, 0, 0);

      const lineCount = rand() < 0.68 ? 1 : rand() < 0.92 ? 2 : 3;
      for (let line = 0; line < lineCount; line++) {
        const product = pickWeighted(PRODUCTS, rand);
        orders.push({
          groupId,
          createdAt,
          ...buildLine(product, rand),
          orderedBy: "staff",
          status: "completed",
        });
      }

      if (rand() < 0.18) {
        const addon = ADD_ONS[Math.floor(rand() * ADD_ONS.length)];
        orders.push({
          groupId,
          createdAt,
          productId: addon.id,
          productName: addon.name,
          size: addon.size,
          quantity: 1,
          revenue: addon.price,
          cogs: Math.round(addon.price * addon.cogsRate),
          needed: {},
          orderedBy: "staff",
          status: "completed",
        });
      }
    }
  }

  return orders;
}

function buildSupplierDeliveries(startDate, endDate) {
  const rand = seededRandom(20261201);
  const deliveries = [];
  const suppliers = ["Bean & Brew Supply", "Cafe Essentials PH", "Daily Dairy Depot", "CupSource Trading"];
  const items = ["Coffee beans and syrups", "Milk and dairy supplies", "Cups, lids, and straws", "Powders and add-ons"];

  for (let cursor = new Date(startDate); cursor <= endDate; cursor.setMonth(cursor.getMonth() + 1)) {
    for (let i = 0; i < 3; i++) {
      const createdAt = new Date(cursor.getFullYear(), cursor.getMonth(), 3 + i * 9, 10 + i, 0, 0);
      deliveries.push({
        supplier: suppliers[i % suppliers.length],
        item: items[i % items.length],
        qty: 1,
        cost: Math.round(2800 + rand() * 4200),
        createdBy: "admin",
        createdAt,
      });
    }
  }

  return deliveries;
}

async function printSummary(label) {
  const [orders, deliveries, inventory] = await Promise.all([
    Order.countDocuments({ groupId: /^SEED-/ }),
    SupplierDelivery.countDocuments({ createdBy: "admin", supplier: { $in: ["Bean & Brew Supply", "Cafe Essentials PH", "Daily Dairy Depot", "CupSource Trading"] } }),
    Inventory.findOne(),
  ]);

  console.log(`\n${label}`);
  console.table({
    seeded_order_lines: orders,
    seeded_supplier_deliveries: deliveries,
    inventory_docs: inventory ? 1 : 0,
  });
}

async function seedSalesData() {
  const confirmed = process.argv.includes("--yes");
  const dryRun = process.argv.includes("--dry-run") || !confirmed;

  if (!process.env.MONGO_URI) {
    throw new Error("MONGO_URI is missing. Add it to .env or set it before running this script.");
  }

  const now = new Date();
  const startDate = new Date(now.getFullYear() - 1, 11, 1, 0, 0, 0, 0);
  const endDate = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999);
  const orders = buildSeedOrders(startDate, endDate);
  const deliveries = buildSupplierDeliveries(startDate, endDate);

  console.log(`Prepared ${orders.length} completed order lines from ${startDate.toDateString()} to ${endDate.toDateString()}.`);
  console.log(`Prepared ${deliveries.length} supplier delivery records.`);

  await mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000,
    maxPoolSize: 10,
  });

  await printSummary("Before seeding");

  if (dryRun) {
    console.log("\nDry run only. No data was changed.");
    console.log("Run `npm run seed:sales -- --yes` to replace old seeded sales data.");
    return;
  }

  await Promise.all([
    Order.deleteMany({ groupId: /^SEED-/ }),
    SupplierDelivery.deleteMany({
      createdBy: "admin",
      supplier: { $in: ["Bean & Brew Supply", "Cafe Essentials PH", "Daily Dairy Depot", "CupSource Trading"] },
    }),
  ]);

  if (orders.length) await Order.insertMany(orders, { ordered: false });
  if (deliveries.length) await SupplierDelivery.insertMany(deliveries, { ordered: false });

  await Inventory.deleteMany({});
  await Inventory.create({ items: { ...HEALTHY_INVENTORY } });
  await Alert.updateMany({ cleared: false }, { $set: { cleared: true, clearedAt: new Date(), clearedBy: "seed:sales" } });

  await printSummary("After seeding");
  console.log("\nSales seed complete. Existing real orders were kept; only previous SEED-* orders were replaced.");
}

seedSalesData()
  .catch((err) => {
    console.error("\nSales seed failed:", err.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
