const mongoose = require('mongoose');

const StudentSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: { type: String, required: true },
  role: { type: String, default: 'student' },
  subjects: { type: String, enum: ['Math', 'Reading', 'Both'], required: true },
  progress: {
    reading: { type: Number, default: 0 },
    math: { type: Number, default: 0 },
  }
}, { timestamps: true });

module.exports = mongoose.model('Student', StudentSchema);
