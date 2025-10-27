const mongoose = require('mongoose');

const AdminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  idNumber: { type: String, required: true },
  fullName: { type: String, required: true },
  startingDate: { type: Date, required: true },
  role: { type: String, default: 'admin' }
}, { timestamps: true });

module.exports = mongoose.model('Admin', AdminSchema);
