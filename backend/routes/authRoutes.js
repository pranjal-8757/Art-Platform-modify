const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const upload = require("../config/multerconfig");

const userModel = require("../models/user.js");
const postModel = require("../models/post.js");

const router = express.Router();
    
router.get('/', (req, res) => {
    res.render("index");
}); 

router.get("/login", (req, res) => {
  res.render("login");
});

router.get("/forgotPassword", (req, res) => {
  res.render("forgotPassword");
});

router.get('/profile/upload', (req, res) => {
    res.render("profileupload");
}); 


router.get('/profile', isLoggedIn, async (req, res) => {
    let user = await userModel.findOne({ email: req.user.email }).populate("posts");
    res.render("profile", { user, loggedInUser: user }); 
});

router.get('/explore', isLoggedIn, async (req, res) => {
  const posts = await postModel.find().populate("user").sort({ _id: -1 });
  res.render("explore", { posts, user: req.user });
});

router.get('/like/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({ _id: req.params.id }).populate("user");

    if (post.likes.indexOf(req.user.userid) === -1) {
        post.likes.push(req.user.userid);
    } else {
        post.likes.splice(post.likes.indexOf(req.user.userid), 1);
    }
    
    await post.save();
    res.redirect("/profile"); 
});

router.get('/edit/:id', isLoggedIn, async (req, res) => {
    let post = await postModel.findOne({ _id: req.params.id }).populate("user");

    if (post.user._id.toString() !== req.user.userid.toString()) {
        return res.status(403).send("Unauthorized");
    }

    res.render("edit", { post });
});

router.get('/delete/:id', isLoggedIn, async (req, res) => {
    await postModel.findOneAndDelete({ _id: req.params.id });
    res.redirect("/profile");
});


router.get('/profile/:id', isLoggedIn, async (req, res) => {
  const user = await userModel.findById(req.params.id).populate("posts");
  const loggedInUser = await userModel.findById(req.user.userid);
  res.render("profile", { user, loggedInUser });
});

router.get("/viewProfile/:id", isLoggedIn, async (req, res) => {
    const user = await userModel
        .findById(req.params.id)
        .populate("posts");

    const loggedInUser = await userModel.findById(req.user.userid);

    res.render("viewProfile", { user, loggedInUser });
});

router.get("/profile", async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");

    const decoded = jwt.verify(token, "shhhh");

    const user = await userModel.findById(decoded.userid);

    const posts = await postModel.find({ user: user._id });

    res.render("profile", { user, posts, loggedInUser: user });
      } catch (err) {
        console.error(err);
        res.redirect("/login");
      }
  });


function isLoggedIn(req, res, next) {
    if (req.cookies.token === "") res.send("You must be logged in");
    else {
        let data = jwt.verify(req.cookies.token, "shhhh");
        req.user = data;
        next(); 
    }  
}


router.post('/register', async (req, res) => {
    let { email, password, username, name, age } = req.body;

    let existingUser = await userModel.findOne({ email });
    if (existingUser) return res.status(500).send("User already registered");

    bcrypt.genSalt(10, (err, salt) => {
        if (err) return res.status(500).send("Error generating salt");

        bcrypt.hash(password, salt, async (err, hash) => {
            if (err) return res.status(500).send("Error hashing password");

            let newUser = await userModel.create({
                username,
                email,
                age,
                name,
                password: hash
            });

            let token = jwt.sign({ email: email, userid: newUser._id }, "shhhh");
            res.cookie("token", token);
            return res.redirect("/profile"); 
        });
    });
});


router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        console.log("Missing email or password");
        return res.status(400).send("Missing credentials");
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            console.log("User not found for email:", email);
            return res.status(400).send("Invalid email or user does not exist");
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            console.log("Password incorrect for email:", email);
            return res.status(400).send("Incorrect password");
        }

        const token = jwt.sign({ email: user.email, userid: user._id }, "shhhh");
        res.cookie("token", token);
        res.redirect("/profile");
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).send("Server error during login");
    }
});

    router.post(
      "/profile/upload",
      isLoggedIn,
      upload.single("image"),
      async (req, res) => {
        try {
          const user = await userModel.findById(req.user.userid);

          if (!req.file) {
            return res.redirect("/profile");
          }

          user.profilepic = req.file.filename;
          await user.save();

          res.redirect("/profile");
        } catch (err) {
          console.error(err);
          res.redirect("/profile");
        }
      }
    );


router.get('/logout', (req, res) => {
    res.cookie("token", "", { httpOnly: true, expires: new Date(0) });
    res.redirect("/login");
});

router.post('/post', isLoggedIn, upload.single("image"), async (req, res) => {
    let user = await userModel.findOne({ email: req.user.email });
    let { content } = req.body;

    let post = await postModel.create({
        user: user._id,
        content,
        image: req.file ? req.file.filename : null 
    });

    user.posts.push(post._id);  
    await user.save();
    res.redirect("/profile");
});


router.post("/update/:id", isLoggedIn, upload.single("image"), async (req, res) => {
    let post = await postModel.findOne({ _id: req.params.id });

    post.content = req.body.content;

    if (req.file) {
        post.image = req.file.filename; 
    }

    await post.save();
    res.redirect("/profile");
});

router.post("/forgotPassword", async (req, res) => {
  const { email } = req.body;

  const user = await userModel.findOne({ email });
  if (!user) {
    return res.send("No user found with this email");
  }

  // generate token
  const token = crypto.randomBytes(32).toString("hex");

  user.resetToken = token;
  user.resetTokenExpiry = Date.now() + 15 * 60 * 1000; // 15 min
  await user.save();

  const resetLink = `http://localhost:3000/reset-password/${token}`;

  // email config
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL,
      pass: process.env.EMAIL_PASS,
    },
  });

  await transporter.sendMail({
    to: user.email,
    subject: "Reset your password",
    html: `
      <p>You requested a password reset</p>
      <a href="${resetLink}">Click here to reset password</a>
      <p>This link expires in 15 minutes</p>
    `,
  });

  res.send("Password reset link sent to your email");
});

router.get("/reset-password/:token", async (req, res) => {
  const user = await userModel.findOne({
    resetToken: req.params.token,
    resetTokenExpiry: { $gt: Date.now() },
  });

  if (!user) {
    return res.send("Token invalid or expired");
  }

  res.render("resetPassword", { token: req.params.token });
});

router.post("/reset-password/:token", async (req, res) => {
  const { password } = req.body;

  const user = await userModel.findOne({
    resetToken: req.params.token,
    resetTokenExpiry: { $gt: Date.now() },
  });

  if (!user) {
    return res.send("Token invalid or expired");
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  user.password = hashedPassword;
  user.resetToken = undefined;
  user.resetTokenExpiry = undefined;

  await user.save();

  res.redirect("/login");
});

router.get('/logout', (req, res) => {
    res.cookie("token", "", { httpOnly: true, expires: new Date(0) });
    res.redirect("/login");
});

module.exports = router;

