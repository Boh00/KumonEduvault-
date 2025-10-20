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

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, './public/Mainhomepage.html'));
});

app.get('/_health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

const MONGO_URI = "mongodb+srv://lancemacalalad1104_db_user:OxUBj8xxF85JYKIA@cluster0.sxatxqn.mongodb.net/Users?retryWrites=true&w=majority";

mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB (Atlas)'))
  .catch(err => {
    console.error('MongoDB connection error:', err);
    process.exit(1);
  });

function getModelByRole(role) {
  if (!role) return null;
  const r = role.toString().toLowerCase();
  if (r === 'admin') return Admin;
  if (r === 'instructor') return Instructor;
  if (r === 'student') return Student;
  return null;
}

// SIGNUP ROUTE (FIXED)
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
    res.json({ message: `${role} signup successful!` });
  } catch (err) {
    console.error('[SIGNUP ERROR]', err);
    res.status(500).json({ message: 'Server error during signup', error: err.message });
  }
});

// LOGIN ROUTE
app.post('/login', async (req, res) => {
  const { email, password, role } = req.body;
  const Model = getModelByRole(role);
  if (!Model) return res.status(400).json({ message: 'Invalid role specified' });

  try {
    const user = await Model.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Email not found' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Incorrect password' });

    res.json({
      message: `${role} login successful!`,
      redirect: `${role.toLowerCase()}HomePage.html`,
      email: user.email,
    });
  } catch (err) {
    console.error('[LOGIN ERROR]', err);
    res.status(500).json({ message: 'Server error during login', error: err.message });
  }
});

// FILE UPLOAD
const storage = multer.memoryStorage();
const upload = multer({ storage });

app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const file = req.file || null;
    const body = req.body || {};

    const studentEmail = body.studentEmail || body.email || null;
    const fileName = body.fileName || (file ? file.originalname : null);
    const worksheetValue = body.worksheetValue || null;
    const instructor = body.instructor || null;

    if (!studentEmail || !fileName || !worksheetValue || !instructor) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    const newUpload = new FileUpload({
      studentEmail,
      fileName,
      worksheetValue,
      instructor,
      uploadedAt: new Date(),
    });

    await newUpload.save();
    res.json({ message: 'File uploaded successfully!' });
  } catch (err) {
    console.error('[UPLOAD ERROR]', err);
    res.status(500).json({ message: 'Server error during file upload', error: err.message });
  }
});

// FETCH UPLOADS
app.get('/uploads', async (req, res) => {
  try {
    const uploads = await FileUpload.find().sort({ uploadedAt: -1 });
    res.json(uploads);
  } catch (err) {
    console.error('[FETCH UPLOADS ERROR]', err);
    res.status(500).json({ message: 'Error fetching uploads', error: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
