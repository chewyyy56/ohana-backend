const mongoose = require("mongoose");
require("dotenv").config();

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

const inventorySchema = new mongoose.Schema(
  {
    items: { type: mongoose.Schema.Types.Mixed, required: true },
  },
  { timestamps: true }
);

const orderSchema = new mongoose.Schema({}, { strict: false });
const alertSchema = new mongoose.Schema({}, { strict: false });
const supplierDeliverySchema = new mongoose.Schema({}, { strict: false });
const auditLogSchema = new mongoose.Schema({}, { strict: false });
const userSchema = new mongoose.Schema({}, { strict: false });

const Inventory = mongoose.model("Inventory", inventorySchema);
const Order = mongoose.model("Order", orderSchema);
const Alert = mongoose.model("Alert", alertSchema);
const SupplierDelivery = mongoose.model("SupplierDelivery", supplierDeliverySchema);
const AuditLog = mongoose.model("AuditLog", auditLogSchema);
const User = mongoose.model("User", userSchema);

async function printCounts(label) {
  const [users, inventories, orders, alerts, deliveries, auditLogs] = await Promise.all([
    User.countDocuments(),
    Inventory.countDocuments(),
    Order.countDocuments(),
    Alert.countDocuments(),
    SupplierDelivery.countDocuments(),
    AuditLog.countDocuments(),
  ]);

  console.log(`\n${label}`);
  console.table({
    users_kept: users,
    inventory_docs: inventories,
    orders,
    alerts,
    supplier_deliveries: deliveries,
    audit_logs: auditLogs,
  });
}

async function resetData() {
  const confirmed = process.argv.includes("--yes");
  const dryRun = process.argv.includes("--dry-run") || !confirmed;

  if (!process.env.MONGO_URI) {
    throw new Error("MONGO_URI is missing. Add it to .env or set it before running this script.");
  }

  await mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 10000,
    connectTimeoutMS: 10000,
    maxPoolSize: 10,
  });

  await printCounts("Current database data");

  if (dryRun) {
    console.log("\nDry run only. No data was changed.");
    console.log("Run `npm run reset:data -- --yes` to delete test data and restore inventory.");
    return;
  }

  await Promise.all([
    Order.deleteMany({}),
    Alert.deleteMany({}),
    SupplierDelivery.deleteMany({}),
    AuditLog.deleteMany({}),
  ]);

  await Inventory.deleteMany({});
  await Inventory.create({ items: { ...INITIAL_INVENTORY } });

  await printCounts("After reset");
  console.log("\nReset complete. User accounts were not touched.");
}

resetData()
  .catch((err) => {
    console.error("\nReset failed:", err.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
