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
const ActivityLog = require('./models/ActivityLog');

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
  if (req.session?.user?.role === 'admin') return next();
  console.warn('[requireAdmin] Unauthorized:', req.session?.user);
  return res.status(403).json({ message: 'Access denied' });
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

// ===== ACTIVITY LOG HELPER =====
async function logActivity({ userId, userRole, userEmail, action }) {
  try {
    const ActivityLog = require('./models/ActivityLog');
    await ActivityLog.create({
      userId,
      userRole,
      userEmail,
      action,
    });
    console.log(`[LOGGED]: ${userEmail} - ${action}`);
  } catch (err) {
    console.error('Error saving activity log:', err);
  }
}

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
      newUser = new Model({
        email: emailTrim,
        password: hashedPassword,
        idNumber: idnum,
        fullName: fullname,
        startingDate: new Date(start),
        role: 'admin'
      });
    } else if (role === 'instructor') {
      if (!idnum || !fullname || !start || !subject) return res.status(400).json({ message: 'Missing instructor data.' });
      if (!['Math', 'Reading'].includes(subject)) return res.status(400).json({ message: 'Subject must be Math or Reading.' });
      newUser = new Model({
        email: emailTrim,
        password: hashedPassword,
        idNumber: idnum,
        fullName: fullname,
        startingDate: new Date(start),
        role: 'instructor',
        subject
      });
    } else if (role === 'student') {
      if (!fullname || !subjects) return res.status(400).json({ message: 'Full name and subjects required.' });
      if (!['Math', 'Reading', 'Both'].includes(subjects)) return res.status(400).json({ message: 'Invalid subjects.' });
      newUser = new Model({
        email: emailTrim,
        password: hashedPassword,
        name: fullname,
        role: 'student',
        subjects
      });
    }

    // ✅ Save user
    await newUser.save();

    // 🧩 Add this block BELOW save() but BEFORE response
    await logActivity({
      userId: newUser._id,
      userRole: role,
      userEmail: emailTrim,
      action: `${role} signed up`,
    });

    // ✅ Send response AFTER logging
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
    if (!emailTrim || !password)
      return res.status(400).json({ message: 'Email and password are required.' });

    const Model = getModelByRole(role);
    if (!Model) return res.status(400).json({ message: 'Invalid role.' });

    const user = await Model.findOne({ email: emailTrim });
    if (!user) return res.status(401).json({ message: 'Email not found.' });

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ message: 'Incorrect password.' });

    const name = user.name || user.fullName || emailTrim.split('@')[0];

    // ✅ Save session
    req.session.user = { email: emailTrim, name, role, id: user._id };

    // ✅ Log the login activity
    await logActivity({
      userId: user._id,
      userRole: role,
      userEmail: emailTrim,
      action: `${role} logged in`,
    });

    // ✅ Prepare and send response
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

app.get('/api/logout', async (req, res) => {
  if (req.session?.user) {
    await logActivity({
      userId: req.session.user.id,
      userRole: req.session.user.role,
      userEmail: req.session.user.email,
      action: `${req.session.user.role} logged out`,
    });
    req.session.destroy(() => res.json({ message: 'Logged out.' }));
  } else {
    res.status(400).json({ message: 'No active session.' });
  }
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

// ==== INSTRUCTOR ROUTE ====
app.get('/instructors', async (req, res) => {
  try {
    const instructors = await Instructor.find().select('fullName subject');
    res.json(instructors);
  } catch (err) {
    console.error('[GET INSTRUCTORS]', err);
    res.status(500).json({ message: 'Failed to load instructors.' });
  }
});

// ===== Upload file =====
const memoryStorage = multer.memoryStorage();
const upload = multer({ storage: memoryStorage });

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const { fileName, worksheetValue, instructor, email } = req.body;

    if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded.' });

    // ensure instructor is an ObjectId reference
    const instructorDoc = await Instructor.findById(instructor);
    if (!instructorDoc) {
      return res.status(400).json({ success: false, message: 'Invalid instructor ID.' });
    }

    // ✅ Save file to MongoDB
    const newFile = new File({
      fileName,
      worksheetValue,
      contentType: req.file.mimetype,
      data: req.file.buffer,
      instructor: instructorDoc._id,
      uploaderEmail: email,
      uploadedAt: new Date(),
    });

    await newFile.save();

    // ✅ Log the upload action
    if (req.session?.user) {
      await logActivity({
        userId: req.session.user.id,
        userRole: req.session.user.role,
        userEmail: req.session.user.email,
        action: `${req.session.user.role} uploaded a file: ${fileName}`,
      });
    } else {
      // fallback if no session exists (e.g. system uploads)
      await logActivity({
        userId: null,
        userRole: 'system',
        userEmail: email || 'unknown',
        action: `File uploaded (no session): ${fileName}`,
      });
    }

    res.json({ success: true, message: '✅ File uploaded successfully to MongoDB!' });
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ success: false, message: 'Server error while uploading.' });
  }
});


// ====== FETCH ALL FILES ======
app.get('/files', async (req, res) => {
  try {
    const files = await File.find()
      .populate('instructor', 'fullName subject')
      .sort({ uploadedAt: -1 });

    const formatted = files.map(file => ({
      _id: file._id,
      fileName: file.fileName,
      worksheetValue: file.worksheetValue,
      fileData: file.data?.toString('base64'),
      contentType: file.contentType,
      uploaderEmail: file.uploaderEmail,
      instructor: file.instructor,
      uploadedAt: file.uploadedAt,
    }));

    res.json(formatted);
  } catch (err) {
    console.error('[FETCH FILES ERROR]', err);
    res.status(500).json({ message: 'Error fetching files' });
  }
});

// ====== FETCH FILE BY ID (for download or preview) ======
app.get('/files/:id', async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found.' });

    res.set('Content-Type', file.contentType);
    res.set('Content-Disposition', `attachment; filename="${file.fileName}"`);
    res.send(file.data);
  } catch (err) {
    console.error('[DOWNLOAD FILE ERROR]', err);
    res.status(500).json({ message: 'Server error.' });
  }
});

// ✅ Instructor gets all student submissions linked to them
app.get('/api/instructor/:id/submissions', async (req, res) => {
  try {
    const instructorId = req.params.id;

    const files = await File.find({ instructor: instructorId })
      .populate('instructor', 'fullName email subject')
      .lean();

    const formattedFiles = files.map(file => ({
      _id: file._id,
      fileName: file.fileName,
      worksheetValue: file.worksheetValue,
      uploaderEmail: file.uploaderEmail,
      uploadedAt: file.uploadedAt,
      contentType: file.contentType,
      base64Data: file.data?.toString('base64'),
      instructor: file.instructor ? {
        fullName: file.instructor.fullName,
        email: file.instructor.email,
        subject: file.instructor.subject
      } : null
    }));

    res.json(formattedFiles);
  } catch (err) {
    console.error('[INSTRUCTOR SUBMISSIONS FETCH ERROR]', err);
    res.status(500).json({ message: 'Error loading submissions', error: err.message });
  }
});

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

    // ✅ Log the edit action
    if (req.session?.user) {
      await logActivity({
        userId: req.session.user.id,
        userRole: req.session.user.role,
        userEmail: req.session.user.email,
        action: `${req.session.user.role} edited file: ${updated.fileName || 'Unnamed File'}`,
      });
    } else {
      // Fallback if session is missing
      await logActivity({
        userId: null,
        userRole: 'system',
        userEmail: 'unknown',
        action: `File edited (no session): ${fileName || 'Unnamed File'}`,
      });
    }

    res.json({ message: '✅ File updated successfully', file: updated });
  } catch (err) {
    console.error('[UPDATE SUBMISSION ERROR]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// 🗑️ Delete a submission
app.delete('/api/instructor/submissions/:fileId', async (req, res) => {
  try {
    const { fileId } = req.params;
    const deleted = await File.findByIdAndDelete(fileId);

    if (!deleted) return res.status(404).json({ message: 'File not found' });

    // ✅ Log the delete action
    if (req.session?.user) {
      await logActivity({
        userId: req.session.user.id,
        userRole: req.session.user.role,
        userEmail: req.session.user.email,
        action: `${req.session.user.role} deleted file: ${deleted.fileName || 'Unnamed File'}`,
      });
    } else {
      // Fallback in case session is missing
      await logActivity({
        userId: null,
        userRole: 'system',
        userEmail: 'unknown',
        action: `File deleted (no session): ${deleted.fileName || 'Unnamed File'}`,
      });
    }

    res.json({ message: '🗑️ File deleted successfully' });
  } catch (err) {
    console.error('[DELETE SUBMISSION ERROR]', err);
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

    // ✅ Log instructor activity
    await logActivity({
      userId: req.session.user.id,
      userRole: req.session.user.role,
      userEmail: req.session.user.email,
      action: `Instructor updated file: ${updated.fileName || 'Unnamed'} (${updated._id})`,
    });

    res.json({ message: '✅ File updated successfully', file: updated });
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

    // ✅ Log instructor activity
    await logActivity({
      userId: req.session.user.id,
      userRole: req.session.user.role,
      userEmail: req.session.user.email,
      action: `Instructor deleted file: ${deleted.fileName || 'Unnamed'} (${deleted._id})`,
    });

    res.json({ message: '🗑️ File deleted successfully' });
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
      instructor: req.session.user.id,
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
app.get(['/admin/users', '/api/admin/users'], async (req, res) => {
  console.log('---- /admin/users CALLED ----');
  console.log('Session:', req.session?.user);

  // quick guard
  if (!req.session?.user || req.session.user.role?.toLowerCase() !== 'admin') {
    console.log('Access denied - no admin session');
    return res.status(403).json({ message: 'Access denied (not admin)' });
  }

  try {
    const students = await Student.find().select('-password').lean();
    const instructors = await Instructor.find().select('-password').lean();
    const admins = await Admin.find().select('-password').lean();

    const mapStudent = s => ({ _id: s._id, name: s.name, email: s.email, role: 'Student' });
    const mapInstructor = i => ({ _id: i._id, name: i.fullName, email: i.email, role: 'Instructor' });
    const mapAdmin = a => ({ _id: a._id, name: a.fullName, email: a.email, role: 'Admin' });

    const payload = [...students.map(mapStudent), ...instructors.map(mapInstructor), ...admins.map(mapAdmin)];

    console.log(`Returning ${payload.length} users`);
    res.json(payload);
  } catch (err) {
    console.error('[GET /admin/users] error:', err);
    res.status(500).json({ message: 'Server error', error: err.message });
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
      await Student.findByIdAndUpdate(id, {
        name: body.name,
        email: body.email,
        subjects: body.subjects,
      });

      // ✅ Log activity
      await logActivity({
        userId: req.session.user.id,
        userRole: req.session.user.role,
        userEmail: req.session.user.email,
        action: `Admin updated Student: ${body.name || found.name} (${body.email || found.email})`,
      });

      return res.json({ message: 'Student updated' });
    }

    else if (found.role === 'Instructor') {
      await Instructor.findByIdAndUpdate(id, {
        fullName: body.name,
        email: body.email,
        subject: body.subject,
        idNumber: body.idNumber,
      });

      await logActivity({
        userId: req.session.user.id,
        userRole: req.session.user.role,
        userEmail: req.session.user.email,
        action: `Admin updated Instructor: ${body.name || found.name} (${body.email || found.email})`,
      });

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

    // ✅ Log deletion
    await logActivity({
      userId: req.session.user.id,
      userRole: req.session.user.role,
      userEmail: req.session.user.email,
      action: `Admin deleted ${found.role}: ${found.name} (${found.email})`,
    });

    return res.json({ message: `${found.role} deleted` });
  } catch (err) {
    console.error('[DELETE /admin/users/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});


// ====== ADMIN FILE MANAGEMENT API ======

app.get('/admin/files', requireAdmin, async (req, res) => {
  try {
    const files = await File.find()
      .populate('instructor', 'fullName email')
      .sort({ uploadedAt: -1 })
      .lean();

    const payload = files.map(f => ({
      _id: f._id,
      fileName: f.fileName,
      worksheetValue: f.worksheetValue || 'Untitled Worksheet',
      uploaderEmail: f.uploaderEmail || 'Unknown',
      instructor: f.instructor ? f.instructor.fullName : '—',
      contentType: f.contentType,
      uploadedAt: f.uploadedAt
    }));

    res.json(payload);
  } catch (err) {
    console.error('[GET /admin/files]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// DELETE a file
app.delete('/admin/files/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const file = await File.findById(id);
    if (!file) return res.status(404).json({ message: 'File not found' });

    await File.findByIdAndDelete(id);

    // ✅ Log admin action
    await logActivity({
      userId: req.session.user.id,
      userRole: req.session.user.role,
      userEmail: req.session.user.email,
      action: `Admin deleted file: ${file.fileName || 'Unnamed'} (${file._id})`,
    });

    res.json({ message: '🗑️ File deleted successfully' });
  } catch (err) {
    console.error('[DELETE /admin/files/:id]', err);
    res.status(500).json({ message: 'Server error' });
  }
});


//Admin preview files
app.get('/admin/files/:id', requireAdmin, async (req, res) => {
  const file = await File.findById(req.params.id);
  if (!file) return res.status(404).json({ message: 'File not found' });
  res.set('Content-Type', file.contentType);
  res.send(file.data);
});

// ✅ Serve static files *after* all API routes
app.use(express.static(path.join(__dirname, 'public')));

app.get(/.*/, (req, res, next) => {
  if (req.path.startsWith('/api/')) return next(); // skip API routes
  res.sendFile(path.join(__dirname, 'public', 'Mainhomepage.html'));
});

// ====== ACTIVITY LOG API ======

// Log a new activity (for any role)
app.post('/api/logs', async (req, res) => {
  try {
    const { userId, userRole, userEmail, action } = req.body;
    if (!userId || !userRole || !action) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const log = new ActivityLog({ userId, userRole, userEmail, action });
    await log.save();

    res.json({ message: 'Activity logged', log });
  } catch (err) {
    console.error('[POST /api/logs]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Get logs for the current logged-in user (Student/Instructor)
app.get('/api/logs/me', async (req, res) => {
  try {
    const user = req.session.user;
    if (!user) return res.status(401).json({ message: 'Unauthorized' });

    const logs = await ActivityLog.find({ userId: user._id })
      .sort({ timestamp: -1 })
      .lean();

    res.json(logs);
  } catch (err) {
    console.error('[GET /api/logs/me]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Admin: Get all activity logs
app.get('/admin/logs', requireAdmin, async (req, res) => {
  try {
    const logs = await ActivityLog.find()
      .populate('userId', 'fullName email')
      .sort({ timestamp: -1 })
      .lean();

    res.json(logs);
  } catch (err) {
    console.error('[GET /admin/logs]', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// ====== ROOT PAGE ======
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'public', 'Mainhomepage.html')));

// ====== START SERVER ======
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
