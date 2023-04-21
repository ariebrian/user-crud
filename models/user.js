const mongoose = require('mongoose');

const user = new mongoose.Schema({
    name: {
        required: true,
        type: String
    },
    role: {
        required: true,
        type: String
    },
    password: {
        required: true,
        type: String
    },
})

const User = mongoose.model('User', user);

module.exports = User;