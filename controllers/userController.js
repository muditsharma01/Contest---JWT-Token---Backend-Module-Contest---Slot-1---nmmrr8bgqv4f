const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const secretKey = 'newtonSchoolContest';

const registerUser = async (req, res) => {
  try {
    const { username, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({
      username,
      password: hashedPassword,
    });

    const savedUser = await user.save();

    res.status(201).json(savedUser);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

const loginUser = async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find the user in the database by username
    const user = await User.findOne({ username });

    // Check if the user exists and if the provided password is correct
    if (user && (await bcrypt.compare(password, user.password))) {
      // Generate JWT token with user information
      const token = jwt.sign({ username: user.username }, secretKey, {
        expiresIn: '1h', // Token expiration time (e.g., 1 hour)
      });

      // Send the token as a JSON response
      res.status(200).json({ token });
    } else {
      // Invalid username or password
      res.status(401).json({ error: 'Invalid username or password' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

module.exports = { registerUser, loginUser };
