const express = require('express');
const mongoose = require('mongoose');

require('dotenv').config();

const mongoString = process.env.DATABASE_URL
mongoose.connect(mongoString);
const database = mongoose.connection

database.on('error', (error) => {
    console.log(error)
})

database.once('connected', () => {
    console.log('Database Connected');
})

const app = express();

app.use(express.json());

const userRoutes = require('./routes/user-routes');
app.use('/api', userRoutes);


app.listen(3000, () => {
    console.log(`Server Started at ${3000}`)
})

