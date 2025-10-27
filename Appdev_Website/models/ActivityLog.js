const mongoose = require('mongoose');

const activityLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    refPath: 'userRole', // dynamic reference (Student, Instructor, or Admin)
    required: true,
  },
  userRole: {
    type: String,
    enum: ['student', 'instructor', 'admin'],
    required: true,
  },
  userEmail: { type: String, required: true },
  action: { type: String, required: true },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model('ActivityLog', activityLogSchema);
