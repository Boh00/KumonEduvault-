const mongoose = require('mongoose');

const fileUploadSchema = new mongoose.Schema({
  studentEmail: { type: String, required: true },
  fileName: { type: String, required: true },
  worksheetValue: { type: String },
  instructor: { type: String },
  fileData: { type: Buffer },
  fileType: { type: String },  
  uploadedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('FileUpload', fileUploadSchema, 'fileuploads');
