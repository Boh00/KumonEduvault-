const mongoose = require('mongoose');

const InstructorSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  idNumber: { type: String, required: true },
  fullName: { type: String, required: true },
  startingDate: { type: Date, required: true },
  role: { type: String, default: 'instructor' },
  subject: { type: String, enum: ['Math', 'Reading'], required: true }
}, { timestamps: true });

module.exports = mongoose.model('Instructor', InstructorSchema);
