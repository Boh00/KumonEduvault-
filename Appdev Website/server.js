const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const session = require('express-session'); // ✅ Added for session management

const Admin = require('./models/Admin');
const Instructor = require('./models/Instructor');
const Student = require('./models/Student');
const FileUpload = require('./models/FileUpload');
const ActivityLog = require('./models/ActivityLog');

const app = express();

// ====== MIDDLEWARE ======
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// ✅ Session setup
app.use(session({
  secret: 'super-secret-session-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: 1000 * 60 * 60 * 2
  }
}));

// ====== DEFAULT ROUTES ======
app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, './public/Mainhomepage.html'));
}); 

app.get('/_health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});


// ====== DATABASE CONNECTION ======
mongoose.connect(
  "mongodb+srv://lancemacalalad1104_db_user:OxUBj8xxF85JYKIA@cluster0.sxatxqn.mongodb.net/Users?retryWrites=true&w=majority",
  { useNewUrlParser: true, useUnifiedTopology: true }
).then(() => console.log('✅ Connected to MongoDB'))
 .catch(err => {
   console.error('MongoDB connection error:', err);
   process.exit(1);
 });

// ====== ROLE HANDLER ======
function getModelByRole(role) {
  if (!role) return null;
  const r = role.toLowerCase();
  if (r === 'admin') return Admin;
  if (r === 'instructor') return Instructor;
  if (r === 'student') return Student;
  return null;
}

// ====== SIGNUP ======
app.post('/signup', async (req, res) => {
  try {
    // normalize likely incoming names from different frontends
    const email = (req.body.email || '').toString().trim();
    const password = (req.body.password || '').toString();
    const roleRaw = (req.body.role || '').toString().trim();
    const role = roleRaw.toLowerCase();

    // Accept many variants of the instructor fields
    const idNumber = req.body.idNumber || req.body.idnum || req.body.id || req.body['ID Number'] || null;
    const fullName = req.body.fullName || req.body.fullname || req.body.name || null;
    const startingDateRaw = req.body.startingDate || req.body.start || req.body.starting || null;
    const startingDate = startingDateRaw ? new Date(startingDateRaw) : null;

    console.log('[SIGNUP] payload normalized:', { email, role, idNumber, fullName, startingDateRaw });

    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required.' });
    }

    const Model = getModelByRole(role);
    if (!Model) return res.status(400).json({ message: 'Invalid role specified.' });

    const existing = await Model.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists.' });

    const hashedPassword = await bcrypt.hash(password, 10);

    let newUser;
    if (role === 'instructor' || role === 'admin') {
      if (!idNumber || !fullName || !startingDateRaw) {
        return res.status(400).json({ message: 'Instructor/Admin requires idNumber, fullName and startingDate.' });
      }
      if (isNaN(startingDate.getTime())) {
        return res.status(400).json({ message: 'Invalid startingDate format.' });
      }

      // ensure the object keys match your Instructor schema (case-sensitive)
      newUser = new Model({
        email,
        password: hashedPassword,
        idNumber: idNumber.toString(),
        fullName: fullName.toString(),
        startingDate,
        role: role
      });
    } else if (role === 'student') {
      if (!fullName) return res.status(400).json({ message: 'Student name is required.' });
      newUser = new Model({
        name: fullName,
        email,
        password: hashedPassword,
        role: 'student'
      });
    } else {
      return res.status(400).json({ message: 'Invalid role specified.' });
    }

    await newUser.save();

    // create activity log (include fields required by your ActivityLog schema)
    await ActivityLog.create({
      userEmail: email,
      studentEmail: email, // include if your ActivityLog schema requires studentEmail
      userRole: role,
      action: 'Signup',
      remarks: `${role} account created`
    });

    return res.status(201).json({ message: `${role} signup successful!` });
  } catch (err) {
    console.error('[SIGNUP ERROR]', err);
    if (err.name === 'ValidationError') {
      return res.status(400).json({ message: 'Validation failed', error: err.message, details: err.errors });
    }
    return res.status(500).json({ message: 'Server error during signup', error: err.message });
  }
});

// ====== LOGIN ======
app.post('/login', async (req, res) => {
  try {
    const email = (req.body.email || '').toString().trim();
    const password = (req.body.password || '').toString();
    const role = (req.body.role || '').toString().toLowerCase();

    if (!email || !password) return res.status(400).json({ message: 'Missing login data' });

    const Model = getModelByRole(role);
    if (!Model) return res.status(400).json({ message: 'Invalid role specified' });

    const user = await Model.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Email not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

    const name = user.name || user.fullName || user.fullname || email.split('@')[0];

    // Save session
    req.session.user = { email, name, role };

    // Log login
    await ActivityLog.create({
      userEmail: email,
      studentEmail: email, // include if your ActivityLog schema requires it
      userRole: role,
      action: 'User Logged In'
    });

    return res.json({
      message: `${role} login successful!`,
      redirect: `${role}HomePage.html`,
      email,
      name,
      role
    });
  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    return res.status(500).json({ message: 'Server error during login', error: err.message });
  }
});



// ====== SESSION CHECK ======
app.get('/session-check', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.status(401).json({ loggedIn: false, message: 'No user session found' });
  }
});

// ====== LOGOUT ======
app.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(() => res.json({ message: 'User logged out successfully' }));
  } else {
    res.status(400).json({ message: 'No active session to destroy' });
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
app.get('/activity/:email', async (req, res) => {
  try {
    const email = req.params.email;
    const role = req.query.role || 'student';

    if (!req.session.user || req.session.user.email !== email) {
      return res.status(401).json({ message: 'No user session found. Please log in again.' });
    }

    const logs = role.toLowerCase() === 'admin'
      ? await ActivityLog.find().sort({ timestamp: -1 })
      : await ActivityLog.find({ userEmail: email }).sort({ timestamp: -1 });

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
