const mongoose = require('mongoose');

const activityLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'userRole',
    required: true,
  },
  userRole: {
    type: String,
    enum: ['Student', 'Instructor', 'Admin'],
    required: true,
  },
  userEmail: { type: String, required: true },
  action: { type: String, required: true },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

module.exports =
  mongoose.models.ActivityLog ||
  mongoose.model('ActivityLog', activityLogSchema);
