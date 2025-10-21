const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcryptjs');

const Admin = require('./models/Admin');
const Instructor = require('./models/Instructor');
const Student = require('./models/Student');
const FileUpload = require('./models/FileUpload');
const ActivityLog = require('./models/ActivityLog');

const app = express();

app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, './public/Mainhomepage.html'));
});

app.get('/_health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

// ====== DATABASE CONNECTION ======
const MONGO_URI =
  "mongodb+srv://lancemacalalad1104_db_user:OxUBj8xxF85JYKIA@cluster0.sxatxqn.mongodb.net/Users?retryWrites=true&w=majority";

mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB (Atlas)'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

// ====== ROLE HANDLER ======
function getModelByRole(role) {
  if (!role) return null;
  const r = role.toString().toLowerCase();
  if (r === 'admin') return Admin;
  if (r === 'instructor') return Instructor;
  if (r === 'student') return Student;
  return null;
}

// ====== SIGNUP ======
app.post('/signup', async (req, res) => {
  const { email, password, role, idNumber, fullName, startingDate, name } = req.body;
  const Model = getModelByRole(role);
  if (!Model) return res.status(400).json({ message: 'Invalid role specified' });

  try {
    const existing = await Model.findOne({ email }).lean();
    if (existing) return res.status(400).json({ message: 'Email already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    let newUser;

    if (role === 'instructor' || role === 'admin') {
      newUser = new Model({
        email,
        password: hashedPassword,
        idnum: idNumber,
        fullname: fullName,
        start: startingDate,
      });
    } else if (role === 'student') {
      newUser = new Model({
        name,
        email,
        password: hashedPassword,
        role: 'Student',
      });
    } else {
      return res.status(400).json({ message: 'Invalid role specified' });
    }

    await newUser.save();

    await ActivityLog.create({
      userEmail: email,
      userRole: role.toLowerCase(),
      action: 'Signup',
      remarks: `${role} account created`,
    });

    res.json({ message: `${role} signup successful!` });
  } catch (err) {
    console.error('[SIGNUP ERROR]', err);
    res.status(500).json({ message: 'Server error during signup', error: err.message });
  }
});

// ====== LOGIN ======
app.post('/login', async (req, res) => {
  console.log('[LOGIN] Request body:', req.body);

  if (!req.body || !req.body.email) {
    return res.status(400).json({ message: 'Missing login data' });
  }

  const { email, password, role } = req.body;
  const Model = getModelByRole(role);
  if (!Model) return res.status(400).json({ message: 'Invalid role specified' });

  try {
    const user = await Model.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Email not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

    const name = user.name || user.fullname || user.email.split('@')[0];

    // Log the login event
    await ActivityLog.create({
      userEmail: email,
      userRole: role.toLowerCase(),
      action: 'User Logged In',
    });

    res.json({
      message: `${role} login successful!`,
      redirect: `${role.toLowerCase()}HomePage.html`,
      email: user.email,
      name,
      role: role.toLowerCase(),
    });
  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    res.status(500).json({ message: 'Server error during login', error: err.message });
  }
});

// ====== FILE UPLOAD ======
const storage = multer.memoryStorage();
const upload = multer({
  storage,
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['image/png', 'image/jpeg', 'image/jpg', 'application/pdf'];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error('Only PNG, JPG, JPEG, or PDF files are allowed.'));
  },
});

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const { studentEmail, fileName, worksheetValue, instructor, role } = req.body;
    if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });

    const newUpload = new FileUpload({
      studentEmail,
      fileName,
      worksheetValue,
      instructor,
      fileData: req.file.buffer,
      fileType: req.file.mimetype,
    });

    await newUpload.save();

    await ActivityLog.create({
      userEmail: studentEmail,
      userRole: role ? role.toLowerCase() : 'student',
      action: 'File Upload',
      fileName,
      remarks: `Uploaded (${req.file.mimetype})`,
    });

    res.json({ message: 'File uploaded successfully!' });
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ message: 'Server error during file upload', error: err.message });
  }
});

// ====== FILE DOWNLOAD ======
app.get('/file/:id', async (req, res) => {
  try {
    const file = await FileUpload.findById(req.params.id);
    if (!file) return res.status(404).send('File not found');

    await ActivityLog.create({
      userEmail: file.studentEmail,
      userRole: 'student',
      action: 'File Download',
      fileName: file.fileName,
      remarks: `Downloaded (${file.fileType})`,
    });

    res.set({
      'Content-Type': file.fileType,
      'Content-Disposition': `attachment; filename="${encodeURIComponent(file.fileName || 'download')}${getExtension(file.fileType)}"`,
    });

    res.send(file.fileData);
  } catch (err) {
    console.error('[FILE FETCH ERROR]', err);
    res.status(500).send('Server error while fetching file');
  }
});

// ====== ACTIVITY LOG FETCH ======
// Admin can view all, others only their own
app.get('/activity', async (req, res) => {
  try {
    const { email, role } = req.query;

    if (!email || !role)
      return res.status(400).json({ message: 'Email and role are required' });

    let logs;
    if (role.toLowerCase() === 'admin') {
      logs = await ActivityLog.find().sort({ timestamp: -1 }); // all logs
    } else {
      logs = await ActivityLog.find({ userEmail: email }).sort({ timestamp: -1 }); // own logs
    }

    res.json(logs);
  } catch (err) {
    console.error('[FETCH ACTIVITY ERROR]', err);
    res.status(500).json({ message: 'Error fetching activity logs', error: err.message });
  }
});

// ====== FILE LIST ======
app.get('/uploads', async (req, res) => {
  try {
    const uploads = await FileUpload.find().sort({ uploadDate: -1 });
    res.json(uploads);
  } catch (err) {
    console.error('[FETCH UPLOADS ERROR]', err);
    res.status(500).json({ message: 'Error fetching uploads', error: err.message });
  }
});

// ====== STUDENT FILES ======
app.get('/uploads/:email', async (req, res) => {
  try {
    const uploads = await FileUpload.find({ studentEmail: req.params.email }).sort({ uploadDate: -1 });
    res.json(uploads);
  } catch (err) {
    console.error('[FETCH STUDENT UPLOADS ERROR]', err);
    res.status(500).json({ message: 'Error fetching student uploads', error: err.message });
  }
});

// ====== FILE EXTENSION HANDLER ======
function getExtension(mime) {
  if (mime === 'image/png') return '.png';
  if (mime === 'image/jpeg') return '.jpg';
  if (mime === 'application/pdf') return '.pdf';
  return '';
}

// ====== SERVER START ======
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
