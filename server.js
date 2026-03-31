const express = require('express');
const mongoose = require('mongoose');
require('dotenv').config();

console.log('Loaded server.js');
console.log('Has MONGO_URI?', !!process.env.MONGO_URI);

const app = express();

async function start() {
  console.log('start() called');
  try {
    console.log('connecting to mongo...');
    await mongoose.connect(process.env.MONGO_URI);
    console.log('MongoDB connected');

    app.get('/', (req, res) => res.json({ ok: true }));

    app.listen(5000, '0.0.0.0', () => {
      console.log('Server running on 5000');
    });
  } catch (err) {
    console.error('Startup error:', err.message);
  }
}

start();
