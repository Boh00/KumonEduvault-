const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

const Admin = require('./models/Admin');
const Instructor = require('./models/Instructor');
const Student = require('./models/Student');

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
  .then(() => console.log('Connected to MongoDB (atlas)'))
  .catch(err => {
    console.error('MongoDB connection error:', err && err.stack ? err.stack : err);
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

app.post('/signup', async (req, res) => {
  console.log('[SIGNUP] body:', req.body);
  const { email, password, role, idNumber, fullName, startingDate } = req.body;


  const Model = getModelByRole(role);
  if (!Model) {
    console.warn('[SIGNUP] invalid role:', role);
    return res.status(400).json({ message: 'Invalid role specified' });
  }

  try {
    const existing = await Model.findOne({ email }).lean();
    if (existing) return res.status(400).json({ message: 'Email already exists' });

    let newUser;
    if (role === 'instructor' || role === 'admin') {
      newUser = new Model({
        email,
        idNumber,
        password,
        fullName,
        startingDate
      });
    } else if (role === 'student') {
      newUser = new Model({
        email,
        password
      });
    } else {
      return res.status(400).json({ message: 'Invalid role specified' });
    }

    await newUser.save();
    res.json({ message: `${role} signup successful!` });
  } catch (err) {
    console.error('[SIGNUP] error:', err && err.stack ? err.stack : err);
    res.status(500).json({ message: 'Server error during signup' });
  }
});

app.post('/login', async (req, res) => {
  console.log('[LOGIN] body:', req.body);
  const { email, password, role } = req.body;
  const Model = getModelByRole(role);
  if (!Model) {
    console.warn('[LOGIN] invalid role:', role);
    return res.status(400).json({ message: 'Invalid role specified' });
  }

  try {
    console.log('[LOGIN] using model:', Model.modelName);

    const user = await Model.findOne({ email }).lean();
    if (!user) {
      console.log('[LOGIN] email not found:', email);
      return res.status(401).json({ message: 'Email not found' });
    }

    if (user.password !== password) {
      console.log('[LOGIN] incorrect password for:', email);
      return res.status(401).json({ message: 'Incorrect password' });
    }

    res.json({
      message: `${role} login successful!`,
      redirect: `${role.toLowerCase()}HomePage.html`
    });
  } catch (err) {
    console.error('[LOGIN] server error:', err && err.stack ? err.stack : err);
    res.status(500).json({ message: 'Server error during login' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
