const express = require('express');
const sessionCookie = require('session-cookie');
const passport = require('passport');
const googleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

const app = express();

app.use(sessionCookie({
    name: 'session',
    secret: 'MySecretKey', // In real use, this should be a value from the .env configuration
    maxAge: 3 * 60 * 60 * 1000 // Three hours
}));

// The implementations of serializeUser and deserialize user are trivial when no database is involved.
passport.serializeUser(function(user, cb) {
    cb(null, user);
});

passport.deserializeUser(function(user, cb) {
    cb(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

passport.use(
    new googleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: '/api/v1/auth/google/callback'
    },
    (accessToken, refreshToken, profile, cb) => {
        cb(null, {id: profile.id, userName: profile.displayName, email: profile.emails[0].value});
    }
));

app.get('/auth/google',
    passport.authenticate('google', {scope: [
        'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile'
    ]}));

app.get('/api/v1/auth/google/callback',
    passport.authenticate('google'),
    (req, res) => {
        res.redirect('/status');
    });

app.get('/status', (req, res) => {
    res.json(req.user)
});

app.set('port', 1337);

const http = require('http');
server = http.createServer(app);

server.listen(1337);
console.log("Browse to http://localhost:1337/auth/google to test.");
