const bcrypt = require("bcryptjs");
module.exports = {
  signup: (req, res) => {
    //   pull email and password off of the body request
    const { email, password } = req.body;
    // access database set in index.js
    const db = req.app.get("db");
    // pass in user email to see if use already exists
    db.check_user_exists(email).then(user => {
      // if length is anything other than 0
      if (user.length) {
        // if user exists, we will send a signup error
        res.status(200).send("Email already exists in the database");
      } else {
        //   if user doesnt exist we will create entry in db for user

        // max 12 saltrounds for security
        const saltRounds = 12;
        // generate a unique "salt" string that will be prepended to the password before hashing
        bcrypt.genSalt(saltRounds).then(salt => {
          // hash the plain text password sent by user with the saltrounds to get final hashed password
          bcrypt.hash(password, salt).then(hashedPassword => {
            //   after hashing password is successful we will store the users data in the db
            db.create_user([email, hashedPassword]).then(loggedInUser => {
              // pull the same user that was just created minus thier password and set to a session
              req.session.user = {
                id: loggedInUser[0].id,
                email: loggedInUser[0].email
              };
              //   send the users session object back to the front as the response
              res.status(200).send(req.session.user);
            });
          });
        });
      }
    });
  },
  login: async (req, res) => {
    const { email, password } = req.body;
    const db = req.app.get("db");

    let userFound = await db.check_user_exists(email);
    if (!userFound[0]) {
      res.status(200).send("Incorrect email, please try again");
    }
    let result = bcrypt.compare(password, userFound[0].user_password);
    if (result) {
      req.session.user = { id: userFound[0].id, email: userFound[0].email };
      res.status(200).send(req.session.user);
    } else {
      res.status(200).send("incorrect email/password");
    }
  },
  logout: (req, res) => {
    req.session.destroy();
    res.sendStatus(200);
  },
  getSession: (req, res) => {
    if (req.session.user) {
      res.status(200).send(req.session.user);
    } else {
      res.status(401).send("Please Log in");
    }
  }
};
