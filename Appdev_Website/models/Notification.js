const mongoose = require('mongoose');

const NotificationSchema = new mongoose.Schema({
  recipient: { type: mongoose.Schema.Types.ObjectId, required: true },
  recipientModel: { type: String, enum: ['Student','Instructor','Admin'], required: true },
  sender: { type: mongoose.Schema.Types.ObjectId },
  senderModel: { type: String, enum: ['Student','Instructor','Admin'] },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Notification', NotificationSchema);
