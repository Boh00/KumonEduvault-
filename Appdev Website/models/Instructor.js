const mongoose = require('mongoose');

const instructorSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  idnum: { type: String },
  fullname: { type: String },
  start: { type: Date }
});

module.exports = mongoose.model('Instructor', instructorSchema, 'Instructors');