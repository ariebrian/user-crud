const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'Authentication failed: Missing token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).json({ message: 'Authentication failed: Invalid token' });
  }
};

const isAdmin = (req, res, next) => {
    console.log(req.user)
    if (req.user.role !== 'Admin') {
      return res.status(403).json({ message: 'Access denied' });
    }
    next();
  };
  
module.exports = { auth, isAdmin };
