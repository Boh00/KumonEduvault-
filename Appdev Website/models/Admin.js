const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  idnum: { type: String },
  fullname: { type: String },  
  start: { type: String }       
});

module.exports = mongoose.model('Admin', adminSchema, 'Admin');
