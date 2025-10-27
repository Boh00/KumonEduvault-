const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');

const Admin = require('./models/Admin');
const Instructor = require('./models/Instructor');
const Student = require('./models/Student');
const Notification = require('./models/Notification');
const File = require('./models/File');

const app = express();


// ====== MIDDLEWARE ======
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: 'super-secret-session-key',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 2 }
}));

// ====== Middleware: Admin Auth Check ======
function requireAdmin(req, res, next) {
  if (!req.session?.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
}

// ====== DATABASE ======
mongoose.connect(
  "mongodb+srv://lancemacalalad1104_db_user:OxUBj8xxF85JYKIA@cluster0.sxatxqn.mongodb.net/Users?retryWrites=true&w=majority",
  { useNewUrlParser: true, useUnifiedTopology: true }
)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => { console.error('MongoDB connection error:', err); process.exit(1); });

// ====== ROLE HANDLER ======
const getModelByRole = (role) => {
  if (!role) return null;
  switch (role.toLowerCase()) {
    case 'admin': return Admin;
    case 'instructor': return Instructor;
    case 'student': return Student;
    default: return null;
  }
};

// ====== AUTH ROUTES ======
app.post('/signup', async (req, res) => {
  try {
    const { email = '', password = '', role = '', idnum, fullname, start, subject, subjects } = req.body;
    const emailTrim = email.trim().toLowerCase();
    if (!emailTrim || !password) return res.status(400).json({ message: 'Email and password are required.' });
    if (password.length < 6) return res.status(400).json({ message: 'Password must be at least 6 characters.' });

    const Model = getModelByRole(role);
    if (!Model) return res.status(400).json({ message: 'Invalid role specified.' });

    if (await Model.findOne({ email: emailTrim }))
      return res.status(400).json({ message: 'Email already exists.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    let newUser;

    if (role === 'admin') {
      if (!idnum || !fullname || !start) return res.status(400).json({ message: 'ID, name, start date required.' });
      newUser = new Model({ email: emailTrim, password: hashedPassword, idNumber: idnum, fullName: fullname, startingDate: new Date(start), role: 'admin' });
    } else if (role === 'instructor') {
      if (!idnum || !fullname || !start || !subject) return res.status(400).json({ message: 'Missing instructor data.' });
      if (!['Math', 'Reading'].includes(subject)) return res.status(400).json({ message: 'Subject must be Math or Reading.' });
      newUser = new Model({ email: emailTrim, password: hashedPassword, idNumber: idnum, fullName: fullname, startingDate: new Date(start), role: 'instructor', subject });
    } else if (role === 'student') {
      if (!fullname || !subjects) return res.status(400).json({ message: 'Full name and subjects required.' });
      if (!['Math', 'Reading', 'Both'].includes(subjects)) return res.status(400).json({ message: 'Invalid subjects.' });
      newUser = new Model({ email: emailTrim, password: hashedPassword, name: fullname, role: 'student', subjects });
    }

    await newUser.save();
    res.status(201).json({ message: `${role} signup successful!` });
  } catch (err) {
    console.error('[SIGNUP ERROR]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email = '', password = '', role = '' } = req.body;
    const emailTrim = email.trim().toLowerCase();
    if (!emailTrim || !password) return res.status(400).json({ message: 'Email and password are required.' });

    const Model = getModelByRole(role);
    if (!Model) return res.status(400).json({ message: 'Invalid role.' });

    const user = await Model.findOne({ email: emailTrim });
    if (!user) return res.status(401).json({ message: 'Email not found.' });
    if (!await bcrypt.compare(password, user.password)) return res.status(401).json({ message: 'Incorrect password.' });

    const name = user.name || user.fullName || emailTrim.split('@')[0];
    req.session.user = { email: emailTrim, name, role, id: user._id };
    const responseData = {
      message: `${role} login successful!`,
      email: emailTrim,
      name,
      role,
      id: user._id,
    };

    if (role === 'instructor' && user.subject) {
      responseData.subject = user.subject;
    }

    res.json(responseData);
  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

app.get('/session-check', (req, res) => {
  req.session.user
    ? res.json({ loggedIn: true, user: req.session.user })
    : res.status(401).json({ loggedIn: false, message: 'No session' });
});

app.post('/logout', (req, res) => {
  req.session ? req.session.destroy(() => res.json({ message: 'Logged out.' })) : res.status(400).json({ message: 'No active session.' });
});

// ====== INSTRUCTOR PROFILE (Protected) ======
app.get('/api/instructor/profile', async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.role !== 'instructor')
      return res.status(401).json({ message: 'Not authorized' });
    const instructor = await Instructor.findById(req.session.user.id).select('-password').lean();
    if (!instructor) return res.status(404).json({ message: 'Instructor not found' });
    res.json(instructor);
  } catch (err) {
    console.error('[PROFILE ERROR]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ====== NOTIFICATIONS ======

// GET instructor notifications
app.get('/notifications/:id/instructor', async (req, res) => {
  try {
    const notifications = await Notification.find({ recipient: req.params.id, recipientModel: 'Instructor' })
      .sort({ createdAt: -1 }).lean();
    res.json(notifications);
  } catch (err) {
    console.error('[GET INSTRUCTOR NOTIFICATIONS]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET student notifications
app.get('/notifications/:id/student', async (req, res) => {
  try {
    const notifications = await Notification.find({ recipient: req.params.id, recipientModel: 'Student' })
      .sort({ createdAt: -1 }).lean();
    res.json(notifications);
  } catch (err) {
    console.error('[GET STUDENT NOTIFICATIONS]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.patch('/notifications/:id/read', async (req, res) => {
  try {
    const notificationId = req.params.id;
    const notification = await Notification.findByIdAndUpdate(
      notificationId,
      { read: true },
      { new: true }
    );
    if (!notification) {
      return res.status(404).json({ message: 'Notification not found' });
    }
    res.json({ message: 'Notification marked as read' });
  } catch (err) {
    console.error('[PATCH NOTIFICATION READ]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// SEND notifications
app.post('/notifications/send', async (req, res) => {
  try {
    const { senderId, senderModel, recipientType, recipientsIds, message, subject } = req.body;
    if (!senderId || !senderModel || !recipientType || !message)
      return res.status(400).json({ message: 'Missing fields' });

    let targets = [], modelName = '';
    if (recipientType === 'students') {
      modelName = 'Student';
      targets = Array.isArray(recipientsIds) && recipientsIds.length
        ? await Student.find({ _id: { $in: recipientsIds } }).select('_id').lean()
        : await Student.find({ $or: [{ subjects: subject }, { subjects: 'Both' }] }).select('_id').lean();
    } else if (recipientType === 'instructors') {
      modelName = 'Instructor';
      targets = Array.isArray(recipientsIds) && recipientsIds.length
        ? await Instructor.find({ _id: { $in: recipientsIds } }).select('_id').lean()
        : await Instructor.find().select('_id').lean();
    } else if (recipientType === 'admins') {
      modelName = 'Admin';
      targets = Array.isArray(recipientsIds) && recipientsIds.length
        ? await Admin.find({ _id: { $in: recipientsIds } }).select('_id').lean()
        : await Admin.find().select('_id').lean();
    } else {
      return res.status(400).json({ message: 'Invalid recipientType' });
    }

    const created = await Promise.all(targets.map(t => new Notification({
      recipient: t._id,
      recipientModel: modelName,
      sender: senderId,
      senderModel,
      message
    }).save()));

    res.json({ message: `Notifications created: ${created.length}`, createdCount: created.length });
  } catch (err) {
    console.error('[SEND NOTIFICATIONS]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// ====== UPLOAD FILES TO MONGODB (Triggered on Form Submit) ======
const memoryStorage = multer.memoryStorage();
const upload = multer({ storage: memoryStorage });

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const { worksheetValue, instructorId } = req.body;
    const subject =
      worksheetValue?.toLowerCase().includes('math') ? 'Math' :
      worksheetValue?.toLowerCase().includes('reading') ? 'Reading' : null;

    const newFile = new File({
      fileName: req.file.originalname,
      data: req.file.buffer,
      contentType: req.file.mimetype,
      size: req.file.size,
      worksheetValue,
      subject,
      instructor: instructorId || null, // ✅ crucial
      uploaderEmail: req.session?.user?.email || 'unknown'
    });

    await newFile.save();
    res.json({ message: 'File uploaded successfully', file: newFile });
  } catch (err) {
    console.error('UPLOAD ERROR:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


// ====== FETCH ALL FILES FROM MONGODB ======
app.get('/files', async (req, res) => {
  try {
    // Return all uploaded files sorted by newest first
    const files = await File.find().sort({ uploadedAt: -1 }).lean();

    res.json(files);
  } catch (err) {
    console.error('[GET FILES]', err);
    res.status(500).json({ message: 'Failed to fetch files.' });
  }
});

app.get('/file/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });
    res.set('Content-Type', file.mimeType);
    res.send(file.data);
  } catch (err) {
    console.error('[GET FILE]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ====== GET CURRENT INSTRUCTOR INFO (used by InstructorFileManagement.html) ======
app.get('/api/instructor/me', async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.role !== 'instructor') {
      return res.status(401).json({ message: 'Not authorized' });
    }

    const instructor = await Instructor.findById(req.session.user.id).select('-password').lean();
    if (!instructor) return res.status(404).json({ message: 'Instructor not found' });

    res.json(instructor);
  } catch (err) {
    console.error('[INSTRUCTOR /me ERROR]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ====== INSTRUCTOR FILE MANAGEMENT ======

// ====== INSTRUCTOR FILES (Filtered by Instructor’s Subject or ID) ======
app.get('/api/instructor/files', async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.role !== 'instructor') {
      return res.status(403).json({ message: 'Access denied' });
    }

    // Get logged-in instructor info
    const instructor = await Instructor.findById(req.session.user.id).lean();
    if (!instructor) return res.status(404).json({ message: 'Instructor not found' });

    const subject = instructor.subject;

    // Fetch all files that belong to this subject OR uploaded by students in this subject
    const files = await File.find({
      $or: [
        { instructor: instructor._id },
        { subject: subject },
        { worksheetValue: { $regex: subject, $options: 'i' } }
      ]
    })
      .sort({ uploadedAt: -1 })
      .lean();

    res.json(files);
  } catch (err) {
    console.error('[INSTRUCTOR FILES FETCH ERROR]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ====== GET STUDENT SUBMISSIONS FOR INSTRUCTOR ======
app.get('/api/instructor/:id/submissions', async (req, res) => {
  try {
    const instructorId = req.params.id;

    // 🧩 Verify instructor exists
    const instructor = await Instructor.findById(instructorId).lean();
    if (!instructor) {
      return res.status(404).json({ message: 'Instructor not found' });
    }

    // 🧠 Fetch files related to the instructor OR their subject
    const files = await File.find({
      $or: [
        { instructor: instructorId },
        { subject: instructor.subject },
        { worksheetValue: { $regex: instructor.subject, $options: 'i' } }
      ]
    })
      .sort({ uploadedAt: -1 })
      .populate('student', 'name email')
      .lean();

    // 🧩 Convert binary data to base64 for frontend preview
    const filesWithBase64 = files.map(f => ({
      _id: f._id,
      fileName: f.fileName,
      subject: f.subject,
      worksheetValue: f.worksheetValue,
      uploadedAt: f.uploadedAt,
      remarks: f.notes || '',
      studentName: f.student?.name || 'Unknown',
      studentEmail: f.student?.email || '',
      uploaderEmail: f.uploaderEmail || '',
      data: f.data ? f.data.toString('base64') : null,
      contentType: f.contentType || 'application/octet-stream'
    }));

    res.json(filesWithBase64);
  } catch (err) {
    console.error('[INSTRUCTOR SUBMISSIONS FETCH ERROR]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Update a file (for editing name/remarks)
app.put('/api/instructor/submissions/:fileId', async (req, res) => {
  try {
    const { fileId } = req.params;
    const { fileName, remarks } = req.body;

    const updated = await File.findByIdAndUpdate(
      fileId,
      { fileName, notes: remarks },
      { new: true }
    );

    if (!updated) return res.status(404).json({ message: 'File not found' });

    res.json({ message: 'File updated successfully', file: updated });
  } catch (err) {
    console.error('[INSTRUCTOR FILE UPDATE ERROR]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// Delete a file
app.delete('/api/instructor/submissions/:fileId', async (req, res) => {
  try {
    const { fileId } = req.params;
    const deleted = await File.findByIdAndDelete(fileId);

    if (!deleted) return res.status(404).json({ message: 'File not found' });

    res.json({ message: 'File deleted successfully' });
  } catch (err) {
    console.error('[DELETE FILE ERROR]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});


// Instructors upload files to students
app.post('/instructor/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.session?.user || req.session.user.role !== 'instructor') {
      return res.status(403).json({ message: 'Unauthorized' });
    }

    const { file } = req;
    const { studentId, fileName, notes } = req.body;

    if (!file || !studentId || !fileName) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    const newFile = new File({
      originalName: file.originalname,
      mimeType: file.mimetype,
      size: file.size,
      data: file.buffer,
      fileName,
      uploaderEmail: req.session.user.email,
      instructor: req.session.user.id,  // logged-in instructor
      student: studentId,
      notes: notes || '',
      uploadedAt: new Date()
    });

    await newFile.save();

    res.json({
      success: true,
      message: '✅ File successfully uploaded to MongoDB and linked to student!',
      fileId: newFile._id
    });
  } catch (err) {
    console.error('[INSTRUCTOR UPLOAD ERROR]', err);
    res.status(500).json({ message: 'File upload failed.', error: err.message });
  }
});

// ====== FETCH ALL FILES FROM MONGODB ======
app.get('/files', async (req, res) => {
  try {
    // Return all uploaded files sorted by newest first
    const files = await File.find().sort({ uploadedAt: -1 }).lean();

    res.json(files);
  } catch (err) {
    console.error('[GET FILES]', err);
    res.status(500).json({ message: 'Failed to fetch files.' });
  }
});


// ====== LOOKUP ROUTES ======
app.get('/students/:subject', async (req, res) => {
  try {
    const { subject } = req.params;
    const allowed = ['Math', 'Reading', 'Both'];
    if (!allowed.includes(subject)) return res.status(400).json({ message: 'Invalid subject' });
    const criteria = subject === 'Both' ? {} : { $or: [{ subjects: subject }, { subjects: 'Both' }] };
    res.json(await Student.find(criteria).select('-password').lean());
  } catch (err) {
    console.error('[GET STUDENTS]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/instructors/:subject', async (req, res) => {
  try {
    const { subject } = req.params;
    const allowed = ['Math', 'Reading', 'Both'];
    if (!allowed.includes(subject)) return res.status(400).json({ message: 'Invalid subject' });
    const filter = subject === 'Both' ? {} : { subject };
    res.json(await Instructor.find(filter).select('_id fullName email subject startingDate').lean());
  } catch (err) {
    console.error('[GET INSTRUCTORS]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get all instructors (for student dropdown)
app.get('/instructors', async (req, res) => {
  try {
    const instructors = await Instructor.find()
      .select('_id fullName email subject startingDate')
      .lean();
    res.json(instructors);
  } catch (err) {
    console.error('[GET ALL INSTRUCTORS]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/student/:email', async (req, res) => {
  try {
    const email = req.params.email.trim().toLowerCase();
    const student = await Student.findOne({ email }).select('-password').lean();
    student ? res.json(student) : res.status(404).json({ message: 'Student not found' });
  } catch (err) {
    console.error('[GET STUDENT]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ====== ADMIN USER MANAGEMENT API ======

// Helper: determine which model contains the given id (searches Admin, Instructor, Student)
async function findUserModelById(id) {
  if (!mongoose.Types.ObjectId.isValid(id)) return null;
  const _id = id;
  let doc = await Student.findById(_id).select('-password').lean();
  if (doc) return { model: Student, doc, role: 'Student' };
  doc = await Instructor.findById(_id).select('-password').lean();
  if (doc) return { model: Instructor, doc, role: 'Instructor' };
  doc = await Admin.findById(_id).select('-password').lean();
  if (doc) return { model: Admin, doc, role: 'Admin' };
  return null;
}

// GET all users (combined)
app.get('/admin/users', requireAdmin, async (req, res) => {
  try {
    const students = await Student.find().select('-password').lean();
    const instructors = await Instructor.find().select('-password').lean();
    const admins = await Admin.find().select('-password').lean();

    // normalize records to a common shape for the frontend
    const mapStudent = s => ({ _id: s._id, name: s.name, email: s.email, role: 'Student', subjects: s.subjects, createdAt: s.createdAt });
    const mapInstructor = i => ({ _id: i._id, name: i.fullName, email: i.email, role: 'Instructor', subject: i.subject, idNumber: i.idNumber, startingDate: i.startingDate, createdAt: i.createdAt });
    const mapAdmin = a => ({ _id: a._id, name: a.fullName, email: a.email, role: 'Admin', idNumber: a.idNumber, startingDate: a.startingDate, createdAt: a.createdAt });

    const payload = [
      ...students.map(mapStudent),
      ...instructors.map(mapInstructor),
      ...admins.map(mapAdmin)
    ];

    res.json(payload);
  } catch (err) {
    console.error('[GET /admin/users]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// POST create user (Admin creates Student / Instructor / Admin)
app.post('/admin/users', requireAdmin, async (req, res) => {
  try {
    const body = req.body;
    const role = (body.role || '').toLowerCase();
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || 'changeme123'; // require password from UI ideally
    if (!email || !role) return res.status(400).json({ message: 'email and role are required' });

    // prevent creating admin by mistake? we allow creating admins but be careful
    const hashed = await bcrypt.hash(password, 10);

    if (role === 'student') {
      const existing = await Student.findOne({ email });
      if (existing) return res.status(400).json({ message: 'Email already exists' });
      const s = new Student({ email, password: hashed, name: body.name || email, subjects: body.subjects || 'Math' });
      await s.save();
      return res.status(201).json({ message: 'Student created', user: { _id: s._id, email: s.email, name: s.name, role: 'Student' } });
    } else if (role === 'instructor') {
      const existing = await Instructor.findOne({ email });
      if (existing) return res.status(400).json({ message: 'Email already exists' });
      if (!body.idNumber || !body.subject) return res.status(400).json({ message: 'idNumber and subject required for instructor' });
      const i = new Instructor({ email, password: hashed, idNumber: body.idNumber, fullName: body.name || email, startingDate: body.startingDate ? new Date(body.startingDate) : new Date(), subject: body.subject });
      await i.save();
      return res.status(201).json({ message: 'Instructor created', user: { _id: i._id, email: i.email, name: i.fullName, role: 'Instructor' } });
    } else if (role === 'admin') {
      const existing = await Admin.findOne({ email });
      if (existing) return res.status(400).json({ message: 'Email already exists' });
      if (!body.idNumber) return res.status(400).json({ message: 'idNumber required for admin' });
      const a = new Admin({ email, password: hashed, idNumber: body.idNumber, fullName: body.name || email, startingDate: body.startingDate ? new Date(body.startingDate) : new Date() });
      await a.save();
      return res.status(201).json({ message: 'Admin created', user: { _id: a._id, email: a.email, name: a.fullName, role: 'Admin' } });
    } else {
      return res.status(400).json({ message: 'Invalid role' });
    }
  } catch (err) {
    console.error('[POST /admin/users]', err);
    res.status(500).json({ message: 'Server error', error: err.message });
  }
});

// PUT update user (cannot edit other Admins)
app.put('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const found = await findUserModelById(id);
    if (!found) return res.status(404).json({ message: 'User not found' });

    if (found.role === 'Admin') {
      return res.status(403).json({ message: 'Editing other Admins is not allowed' });
    }

    const body = req.body;
    if (found.role === 'Student') {
      const data = {};
      if (body.name) data.name = body.name;
      if (body.email) data.email = body.email;
      if (body.subjects) data.subjects = body.subjects;
      await Student.findByIdAndUpdate(id, data, { new: true });
      return res.json({ message: 'Student updated' });
    } else if (found.role === 'Instructor') {
      const data = {};
      if (body.name) data.fullName = body.name;
      if (body.email) data.email = body.email;
      if (body.subject) data.subject = body.subject;
      if (body.idNumber) data.idNumber = body.idNumber;
      await Instructor.findByIdAndUpdate(id, data, { new: true });
      return res.json({ message: 'Instructor updated' });
    }

    res.status(400).json({ message: 'Unhandled role' });
  } catch (err) {
    console.error('[PUT /admin/users/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE user (cannot delete Admins)
app.delete('/admin/users/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const found = await findUserModelById(id);
    if (!found) return res.status(404).json({ message: 'User not found' });

    if (found.role === 'Admin') {
      return res.status(403).json({ message: 'Deleting Admin accounts is not allowed' });
    }

    await found.model.findByIdAndDelete(id);
    return res.json({ message: `${found.role} deleted` });
  } catch (err) {
    console.error('[DELETE /admin/users/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ✅ Serve static files *after* all API routes
app.use(express.static(path.join(__dirname, 'public')));

// ✅ Catch-all route (so HTML files only serve if no API matched)
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next(); // don't serve HTML for API routes
  res.sendFile(path.join(__dirname, 'public', 'Mainhomepage.html'));
});

// ====== ROOT PAGE ======
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'public', 'Mainhomepage.html')));

// ====== START SERVER ======
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
