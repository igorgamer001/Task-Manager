const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');




dotenv.config();

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Failed to connect to MongoDB', err));

// User schema and model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Task schema and model
const taskSchema = new mongoose.Schema({
  title: { type: String, required: true },
  completed: { type: Boolean, default: false },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

const Task = mongoose.model('Task', taskSchema);

// Register a new user
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  
  const userExist = await User.findOne({ email });
  if (userExist) return res.status(400).json({ message: 'User already exists' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ email, password: hashedPassword });

  await newUser.save();
  res.status(201).json({ message: 'User registered successfully' });
});

// Login and get JWT token
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ message: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Middleware to authenticate JWT token
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token' });
    req.userId = decoded.userId;
    next();
  });
};

// Create a new task
app.post('/tasks', authenticate, async (req, res) => {
  const { title } = req.body;
  const task = new Task({ title, userId: req.userId });

  await task.save();
  res.status(201).json({ task });
});

// Get all tasks for the authenticated user
app.get('/tasks', authenticate, async (req, res) => {
  const tasks = await Task.find({ userId: req.userId });
  res.json({ tasks });
});

// Update task completion status
app.put('/tasks/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const { completed } = req.body;

  const task = await Task.findOneAndUpdate({ _id: id, userId: req.userId }, { completed }, { new: true });
  if (!task) return res.status(404).json({ message: 'Task not found' });

  res.json({ task });
});

// Delete a task
app.delete('/tasks/:id', authenticate, async (req, res) => {
  const { id } = req.params;

  const task = await Task.findOneAndDelete({ _id: id, userId: req.userId });
  if (!task) return res.status(404).json({ message: 'Task not found' });

  res.json({ message: 'Task deleted successfully' });
});

// Start server
app.listen(port, () => {
  console.log(`Task Manager API is running at http://localhost:${port}`);
});
