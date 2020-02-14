const knex = require("knex");
const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const cors = require("cors");
const port = process.env.PORT || 5000;

const knexConfig = require("./knexfile.js");

const sessionConfig = {
  name: "gram",
  secret: "bigsecret",
  cookie: {
    secure: process.env.SECURE || false,
    httpOnly: true
  },
  resave: false,
  saveUninitialized: false
};

const allowedOrigins = ["http://localhost:3000"];

const server = express();
server.use(express.json());
server.use(session(sessionConfig));
server.use(
  cors({
    origin: function(origin, callback) {
      // allow requests with no origin
      // (like mobile apps or curl requests)
      if (!origin) return callback(null, true);
      if (allowedOrigins.indexOf(origin) === -1) {
        let msg =
          "The CORS policy for this site does not " +
          "allow access from the specified Origin.";
        return callback(new Error(msg), false);
      }
      return callback(null, true);
    },

    exposedHeaders: ["Content-Length", "X-Foo", "X-Bar"],

    credentials: true
  })
);

const db = knex(knexConfig);

// ============================================================================================================================================= Authorization Middleware <-----------------
// This middleware makes sure that a user is logged in and that they are either the sender or recipient of the messages they are requesting
function rMessage(req, res, next) {
  console.log("middleware session: ", req.session);
  console.log("middleware params: ", req.params);
  if (
    req.session &&
    (req.session.user.username === req.params.senderName || req.session.user.username === req.params.receiverName)
  ) {
    next();
  } else {
    res.status(401).json({ message: "Not Authenticated" });
  }
}

// This middleware makes it so that only the logged in user can send messages under their username
function sMessage(req, res, next) {
  console.log("middleware session: ", req.session);
  console.log("middleware body: ", req.body);
  if (req.session && req.session.user.username === req.body.sender) {
    next();
  } else {
    res.status(401).json({ message: "Not Authenticated" });
  }
}

// ================================================================================================================================================ Endpoints <-----------------------------
// This endpoint makes sure confirms the server is up and running
server.get("/", (req, res) => {
  res.send("Sanity Check");
});

// This endpoint returns a list of all users
server.get("/users", (req, res) => {
  db("users")
    .then(users => {
      res.status(200).json(users);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// This endpoint returns a user by the specified ID
server.get("/users/:id", (req, res) => {
  console.log(req.params);
  db("users")
    .where("id", req.params.id)
    .then(user => {
      res.status(200).json(user);
    })
    .catch(err => {
      res.status(500).json(err);
    });
});

// This endpoint creates a new user
server.post("/users", (req, res) => {
  let creds = req.body;
  console.log(req.body);
  const hash = bcrypt.hashSync(creds.password, 12);
  creds.password = hash;
  db("users")
    .insert(creds)
    .then(user => {
      res.status(201).json(user);
    })
    .catch(err => res.status(500).json(err));
});

// This endpoint returns a list of all messages
server.get("/posts", (req, res) => {
  db("posts")
    .then(posts => {
      res.status(500).json(posts);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// This endpoint creates a new message
server.post("/posts", sMessage, (req, res) => {
  db("posts")
    .insert(req.body)
    .then(post => {
      res.status(201).json(post);
    })
    .catch(err => res.status(500).json(err));
});

// This endpoint gets a list of messages between sent from one specified user to another specified user
server.get("/posts/:senderName/:receiverName", rMessage, (req, res) => {
  console.log("params: ", req.params);
  db("posts")
    .where({ sender: req.params.senderName, receiver: req.params.receiverName })
    .then(post => {
      res.status(200).json(post);
    })
    .catch(err => {
      res.status(500).json(err);
    });
});

// This endpoint logs in a user
server.post("/login", (req, res) => {
  const creds = req.body;
  db("users")
    .where({ username: creds.username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        console.log("user: ", user);
        let userdata = user;
        req.session.user = userdata;
        console.log("session: ", req.session.user);
        res.status(200).json(user);
      } else {
        res.status(401).json({ message: "failure" });
      }
    })
    .catch(err => res.status(500).json(err));
});

// Creates a new contact relationship
server.post("/friends", (req, res) => {
  const friendship = req.body;
  db("friendships")
    .insert(friendship)
    .then(friend => {
      res.status(200).json({ message: "success" });
    })
    .catch(err => res.status(401).json({ message: err }));
});

// Gets all contact relationships
server.get("/friends", (req, res) => {
  db("friendships")
    .then(friendships => {
      res.status(200).json(friendships);
    })
    .catch(err => res.status(401).json({ message: err }));
});

// Gets a users contact relationships
server.get("/friends/:initiator", (req, res) => {
  db("friendships")
    .where({ initiator: req.params.initiator })
    .then(friendships => {
      res.status(200).json(friendships);
    })
    .catch(err => res.status(401).json({ message: err }));
});

// If an endpoint doesnt exist server will return this
server.use(function(req, res) {
  res.status(404).send("Error: 404 This page does not exist");
});

server.listen(port, () => {
  console.log(`server listening on port ${port}`);
});
