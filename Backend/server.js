import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import mongoose from "mongoose";
import session from "express-session";
import MongoStore from "connect-mongo";
import passport from "passport";
import flash from "connect-flash";
import admin from "firebase-admin"; // Import Firebase Admin SDK
import nodemailer from "nodemailer"; // Import nodemailer for Mongoose email verification (optional)
import fs from 'fs';
import dotenv from "dotenv";
dotenv.config();
// const serviceAccount = JSON.parse(fs.readFileSync(new URL('./firebase-admin-sdk.json', import.meta.url)));
const serviceAccount = JSON.parse(process.env.FIREBASE_CONFIG);
serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');


try {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} catch (error) {
  console.error("Error initializing Firebase Admin SDK:", error);
  // Exit the process if Firebase Admin SDK fails to initialize, as core functionality might depend on it.
  process.exit(1);
}

// --- Project Imports ---
import "./config/db.js"; // Your Mongoose database connection configuration
import configurePassport from "./config/passport.js"; // Your Passport.js configuration (for local strategy)
import User from "./models/User.js"; // Your Mongoose User model

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- Express Configuration ---
app.set("views", path.join(__dirname, "../Frontend/views"));
app.set("view engine", "ejs");
app.use(express.static(path.join(__dirname, "../public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Session Middleware ---
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: "sessions",
      ttl: 14 * 24 * 60 * 60, // Session TTL in seconds (14 days)
    }),
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 30, // Cookie TTL in milliseconds (30 days)
      httpOnly: true, // Prevent client-side JavaScript from accessing the cookie
      secure: process.env.NODE_ENV === "production", // Only send cookie over HTTPS in production
    },
  })
);

// --- Passport.js Initialization ---
configurePassport(); // Configures Passport's local strategy for Mongoose users
app.use(passport.initialize());
app.use(passport.session()); // Enables persistent login sessions

// --- Flash Messages Middleware ---
app.use(flash());
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error");
  res.locals.user = req.user || null; // Passport populates req.user if a session exists
  next();
});

// --- Nodemailer Transporter Setup (for Mongoose email verification - optional) ---
// IMPORTANT: Replace with your actual email service credentials from environment variables
const transporter = nodemailer.createTransport({
  service: "gmail", // e.g., 'gmail', 'Outlook', 'SendGrid'
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// --- Email Sending Function (for Mongoose email verification - optional) ---
const sendVerificationEmail = async (userEmail, userName, req) => {
  const loginUrl = `${req.protocol}://${req.get("host")}/login`; // Dynamically generate login URL

  const emailContent = `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Welcome to ForgeFolio!</title>
            <style>
                body { font-family: 'Poppins', sans-serif; background-color: #f4f4f4; margin: 0; padding: 0; }
                .email-container { max-width: 600px; margin: 20px auto; background-color: #ffffff; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
                .header { text-align: center; padding-bottom: 20px; border-bottom: 1px solid #eeeeee; }
                .header img { max-width: 100px; margin-bottom: 10px; }
                .header h1 { color: #333333; font-size: 24px; margin: 0; }
                .content { padding: 20px 0; line-height: 1.6; color: #555555; }
                .button-container { text-align: center; padding: 20px 0; }
                .button { background-color: #111827; color: #ffffff; padding: 12px 25px; border-radius: 5px; text-decoration: none; font-weight: bold; display: inline-block; }
                .footer { text-align: center; padding-top: 20px; border-top: 1px solid #eeeeee; font-size: 12px; color: #aaaaaa; }
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    <img src="https://ibb.co/zV5mFjLp" alt="ForgeFolio Logo">
                    <h1>Welcome to ForgeFolio, ${userName}!</h1>
                </div>
                <div class="content">
                    <p>Thank you for registering with ForgeFolio. We're excited to have you on board!</p>
                    <p>To get started, please click the button below to log in to your account:</p>
                </div>
                <div class="button-container">
                    <a href="${loginUrl}" class="button">Log In to Your Account</a>
                </div>
                <div class="content">
                    <p>If you have any questions, feel free to contact our support team.</p>
                    <p>Best regards,<br>The ForgeFolio Team</p>
                </div>
                <div class="footer">
                    <p>&copy; ${new Date().getFullYear()} ForgeFolio. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
    `;

  let mailOptions = {
    from: process.env.EMAIL_USER, // Sender address
    to: userEmail, // List of receivers
    subject: "Welcome to ForgeFolio - Confirm Your Registration", // Subject line
    html: emailContent, // HTML body
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Verification email sent successfully to " + userEmail);
  } catch (error) {
    console.error("Error sending verification email:", error);
  }
};

// --- Routes ---

// GET / (Register Page - Mongoose Email/Password)
app.get("/", (req, res) => {
  res.render("auth/register");
});

app.get("/check-email", (req, res) => {
  res.render("auth/email-sent");
});

// POST /register (Mongoose Email/Password Registration)
app.post("/register", async (req, res) => {
  const { fullName, email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      req.flash("error_msg", "Email already registered.");
      return res.redirect("/");
    }

    user = new User({ fullName, email, password });
    await user.save();

    // Optional: Send a welcome email for Mongoose registrations
    // Uncomment the line below if you want to send an email for Mongoose registrations
    await sendVerificationEmail(user.email, user.fullName, req);

    req.flash(
      "success_msg",
      "Registration successful! Please log in with your new account."
    );
    res.redirect("/check-email"); // Redirect to login page after Mongoose registration
  } catch (error) {
    console.error("Mongoose Registration error:", error);
    if (error.name === "ValidationError") {
      const messages = Object.values(error.errors).map((val) => val.message);
      req.flash("error_msg", messages.join(", "));
    } else {
      req.flash("error_msg", "Something went wrong during registration.");
    }
    res.redirect("/");
  }
});

// GET /login (Login Page - Mongoose Email/Password)
app.get("/login", (req, res) => {
  res.render("auth/login");
});

// POST /login (Mongoose Email/Password Login)
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

// POST /firebase-auth (Endpoint for Firebase ID Token verification)
app.post("/firebase-auth", async (req, res) => {
  const idToken = req.body.idToken;

  if (!idToken) {
    req.flash("error_msg", "Firebase ID token not provided.");
    return res.status(400).send("ID token missing");
  }

  try {
    // Verify the ID token using Firebase Admin SDK
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const firebaseUid = decodedToken.uid;
    const firebaseEmail = decodedToken.email;
    const firebaseDisplayName = decodedToken.name || firebaseEmail; // Use email if display name is not available

    // Check if user exists in your Mongoose database by email or firebaseUid
    let user = await User.findOne({
      $or: [{ email: firebaseEmail }, { firebaseUid: firebaseUid }],
    });

    if (!user) {
      // If user doesn't exist in Mongoose, create a new one
      user = new User({
        email: firebaseEmail,
        fullName: firebaseDisplayName,
        firebaseUid: firebaseUid,
        // Set password to a placeholder or null as it's Firebase auth
        password: "FIREBASE_AUTH_USER_NO_PASSWORD",
      });
      await user.save();
      console.log("New Mongoose user created from Firebase login:", user.email);
    } else {
      // If user exists, ensure firebaseUid is set and update fullName if needed
      if (!user.firebaseUid || user.firebaseUid !== firebaseUid) {
        user.firebaseUid = firebaseUid;
      }
      if (!user.fullName && firebaseDisplayName) {
        user.fullName = firebaseDisplayName;
      }
      await user.save();
      console.log(
        "Existing Mongoose user logged in/updated via Firebase:",
        user.email
      );
    }

    // Log the user in using Passport (creates a server-side session)
    // This is crucial for req.isAuthenticated() and req.user to work on subsequent requests.
    req.login(user, (err) => {
      if (err) {
        console.error("Passport login error after Firebase auth:", err);
        req.flash(
          "error_msg",
          "Failed to create session after Firebase login."
        );
        return res.status(500).redirect("/login");
      }
      req.flash("success_msg", "Successfully logged in with Firebase!");
      res.status(200).send("Logged in"); // Send success, client will redirect to dashboard
    });
  } catch (error) {
    console.error(
      "Firebase ID token verification or Mongoose operation failed:",
      error
    );
    req.flash(
      "error_msg",
      `Authentication failed: ${error.message || "An unknown error occurred."}`
    );
    res.status(401).redirect("/login");
  }
});

// Middleware to protect routes (checks Passport session)
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  req.flash("error_msg", "Please log in to view this resource.");
  res.redirect("/login");
}

// GET /dashboard (Protected Route)
app.get("/dashboard", isAuthenticated, (req, res) => {
  res.render("dashboard", { user: req.user });
});

// GET /logout
app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.flash("success_msg", "You are logged out.");
    res.redirect("/login");
  });
});

// Start Server
const port = 3000;
app.listen(port, () =>
  console.log(`ForgeFolio running at http://localhost:${port}`)
);
