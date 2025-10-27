const fileSchema = new mongoose.Schema({
  fileName: String,
  data: Buffer,
  contentType: String,
  size: Number,
  worksheetValue: String,
  subject: String,
  instructor: { type: mongoose.Schema.Types.ObjectId, ref: 'Instructor' },
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'Student' },
  uploaderEmail: String,
  notes: String,
  uploadedAt: { type: Date, default: Date.now }
});
