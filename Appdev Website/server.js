const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');

// Import models for each user type
const Admin = require('./models/Admin');
const Instructor = require('./models/Instructor');
const Student = require('./models/Student');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Atlas connection
mongoose.connect("mongodb+srv://lancemacalalad1104_db_user:OxUBj8xxF85JYKIA@cluster0.sxatxqn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection error:', err));

function getModelByRole(role) {
  switch (role.toLowerCase()) {
    case 'admin':
      return Admin;
    case 'instructor':
      return Instructor;
    case 'student':
      return Student;
    default:
      return null;
  }
}

app.post('/signup', async (req, res) => {
  const { email, password, role } = req.body;
  const Model = getModelByRole(role);

  if (!Model) return res.status(400).json({ message: 'Invalid role specified' });

  try {
    const existing = await Model.findOne({ email });
    if (existing) return res.status(400).json({ message: 'Email already exists' });

    const newUser = new Model({ email, password });
    await newUser.save();
    res.json({ message: `${role} signup successful!` });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err });
  }
});


app.post('/login', async (req, res) => {
  const { email, password, role } = req.body;
  const Model = getModelByRole(role);

  if (!Model) return res.status(400).json({ message: 'Invalid role specified' });

  try {
    const user = await Model.findOne({ email, password });
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });

    res.json({
      message: `${role} login successful!`,
      redirect: `${role.toLowerCase()}-homepage.html`
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error', error: err });
  }
});

const PORT = 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
