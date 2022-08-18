const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const { v4: uuidv4 } = require("uuid");

const dbPath = path.resolve(__dirname, "./db.db");
const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (error) => {
  if (error) console.error(`DB Connection Error: ${error?.message}`);
  console.log("DB Connected ~~");
});

// sql query for creating a new table via node
// db.run(`CREATE TABLE users(email, password, id)`);

// close db - better not enabled ~~
// db.close((error) => {
//   if (error) return console.error(`DB Close Erorr: ${error?.message}`);
//   // return console.log("DB Closed ~~");
// });

const port = process.env.PORT || "7284";
const app = express();

// middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// routes
app.post("/register", (req, res) => {
  try {
    const { email, password } = req.body;
    bcrypt.genSalt(10, function (err, salt) {
      if (err) throw new Error(err?.message);

      bcrypt.hash(password, salt, function (err, hash) {
        if (err) throw new Error(err?.message);

        const id = uuidv4();
        const passwordHash = hash;
        const sql = `INSERT INTO users(email, password, id) VALUES(?,?,?)`;

        db.run(sql, [email, passwordHash, id], (error) => {
          if (error)
            console.error(
              `Error occurred during saving to database stage, details: ${error?.message}`
            );

          res.status(201).json({ email, password: passwordHash, id });
        });
      });
    });
  } catch (error) {
    console.error(
      `Error occurred during account registration, details: ${error?.message}`
    );

    res.status(500).json({ message: error?.message });
  }
});

app.post("/login", (req, res) => {
  try {
    const { email, password } = req.body;

    // find the user by email
    const sql = `SELECT * FROM users`;
    db.all(sql, [], (err, rows) => {
      if (err) throw new Error(err?.message);

      const user = rows.find((row) => row.email === email);

      if (!user)
        res.status(404).json({ message: `The user ${email} not found ..` });

      // compare password with password hash
      if (user && user.password)
        bcrypt
          .compare(password, user.password)
          .then((result) =>
            result
              ? res.status(200).json({ message: "logged in successfully ~~" })
              : res.status(401).json({ message: "unable to login .." })
          );
    });
  } catch (error) {
    console.error(
      `Error occurred during account login, details: ${error?.message}`
    );

    res.status(500).json({ message: error?.message });
  }
});

app.listen(port, () => {
  console.log(`App is up and running on ${port} ..`);
});

// references:
// 1. https://www.youtube.com/watch?v=xDYx5UdHwv0
// 2. https://www.youtube.com/watch?v=9yIrM7eZwUE
