const mongoose = require('mongoose');

const FileUploadSchema = new mongoose.Schema({
  studentEmail: { type: String, required: true },
  fileName: { type: String, required: true },
  worksheetValue: { type: String, required: true },
  instructor: { type: String, required: true },
  uploadedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('FileUpload', FileUploadSchema, 'fileuploads');
