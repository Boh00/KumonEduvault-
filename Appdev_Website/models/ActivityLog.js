const mongoose = require('mongoose');

const ActivityLogSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  userRole: { type: String, required: true },
  action: { type: String, required: true },
  fileName: { type: String },
  remarks: { type: String },
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('ActivityLog', ActivityLogSchema, 'activitylogs');
