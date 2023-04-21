const express = require('express');

const router = express.Router()
module.exports = router

const User = require('../models/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { auth, isAdmin } = require('../middleware/auth');

router.post('/create', auth, isAdmin, async (req, res) => {
  try {
    const { name, password, role } = req.body;

    // Check if user with the same email already exists
    const existingUser = await User.findOne({ name });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a new user
    const user = new User({
      name,
      password: hashedPassword,
      role,
    });
    await user.save();

    // Generate a JWT token
    const token = jwt.sign({ userId: user._id, role: user.role }, 'secret_key');

    res.json({ message: 'User created successfully', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

router.post('/login', async (req, res) => {
    try {
      const { name, password } = req.body;
  
      // Find the user with the given email
      const user = await User.findOne({ name });
      if (!user) {
        return res.status(400).json({ message: 'Invalid username or password' });
      }
  
      // Check if the password matches
      const isPasswordMatch = await bcrypt.compare(password, user.password);
      if (!isPasswordMatch) {
        return res.status(400).json({ message: 'Invalid email or password' });
      }
  
      // Generate a JWT token
      const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET);
  
      res.json({ message: 'Login successful', token });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
});

router.get('/user/:userId', auth, async (req, res) => {
    try {
      // Check if the user is an admin or is requesting their own ID
      if (req.user.role !== 'Admin' && req.params.userId !== req.user.userId.toString()) {
        return res.status(403).json({ message: 'Access denied' });
      }
  
      // Find the user with the given ID
      const user = await User.findById(req.params.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      res.json(user);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
});

router.get('/users', auth, isAdmin, async (req, res) => {
    try {
      // Find all users
      const users = await User.find();
      res.json(users);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
});

router.put('/update/:userId', auth, isAdmin, async (req, res) => {
    try {
      // Find user by ID
      const user = await User.findById(req.params.userId);
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      // Update user fields
      user.name = req.body.name || user.name;
      user.role = req.body.role || user.role;
  
      // Check if password is provided
      if (req.body.password) {
        // Hash password with salt
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
  
        // Set password to hashed password
        user.password = hashedPassword;
      }
  
      // Save updated user to database
      const updatedUser = await user.save();
      res.json(updatedUser);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
});

router.delete('/delete/:userId', auth, isAdmin, async (req, res) => {
  try {
    // Check if user exists
    const user = await User.findById(req.params.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if user is trying to delete their own account
    if (req.user.userId.toString() === req.params.userId) {
      return res.status(400).json({ message: 'Cannot delete your own account' });
    }

    // Delete user
    await user.deleteOne();

    res.json({ message: 'User deleted' });
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server error');
  }
});
