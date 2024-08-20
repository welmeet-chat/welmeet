const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const server = require('http').createServer(app);
const io = require('socket.io')(server);

app.use(express.json());

app.use(express.static(__dirname + '/public'));

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

mongoose.connect('mongodb://localhost:27017/mydatabase');

const secretKey = '8iorqve+6rv2HLLuXPIHuWHkpS+OxOhiPzrnWojmH6I=';

const userSchema = new mongoose.Schema({
  username: String,
  password: String
});

const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  text: String,
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now }
});

const Message = mongoose.model('Message', messageSchema);


app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send('User registered');
  } catch (error) {
    res.status(400).send('Error registering user');
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).send('Invalid credentials');
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send('Invalid credentials');
    const token = jwt.sign({ userId: user._id }, secretKey);
    res.redirect(`/dashboard?token=${token}`);
  } catch (error) {
    res.status(500).send('Server error');
  }
});

app.get('/dashboard', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).send('Unauthorized');

  try {
    const decoded = jwt.verify(token, secretKey);
    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).send('Invalid user');

    res.sendFile(__dirname + '/public/dashboard.html');
  } catch (error) {
    res.status(500).send('Server error');
  }
});

app.get('/chat-history', async (req, res) => {
  try {
    const messages = await Message.find().sort({ createdAt: -1 }).limit(20);
    res.json(messages);
  } catch (error) {
    res.status(500).send('Server error');
  }
});

app.get('/home', (req, res) => {
  res.sendFile(__dirname + '/public/home.html');
});

io.on('connection', (socket) => {
  console.log('New client connected');

  const users = {};

  socket.on('login', async (token) => {
    try {
      const decoded = jwt.verify(token, secretKey);
      const user = await User.findById(decoded.userId);
      if (!user) return socket.emit('error', 'Invalid user');
      users[socket.id] = user;
      socket.username = user.username;
    } catch (error) {
      socket.emit('error', 'Invalid token');
    }
  });

  socket.on('message', async (message) => {
    try {
      const newMessage = new Message({ text: message, userId: users[socket.id]._id });
      await newMessage.save();
      io.emit('message', { text: message, username: users[socket.id].username });
    } catch (error) {
      socket.emit('error', 'Error sending message');
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected');
    delete users[socket.id];
  });
});

process.on('SIGINT', () => {
  mongoose.connection.close(() => {
    console.log('Mongoose connection closed');
    process.exit(0);
  });
});

server.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});






