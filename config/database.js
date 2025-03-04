const mongoose = require("mongoose");
const dotenv = require('dotenv');

dotenv.config()
const connectDatabase = () => {
  mongoose
    .connect(process.env.DB_URI, {
      family: 4,
      // useCreateIndex: true,
    })
    .then((data) => {
      console.log(`Mongodb connected with server: ${data.connection.host}`);
    });
};

module.exports = connectDatabase;
