# session-cookie

Maintain small [express](https://expressjs.com/) sessions in a session cookie instead of a database.

Compatible with [passport](https://www.npmjs.com/package/passport) v0.6.0 and v0.7.0

Typically, **express** user sessions are stored in a local database of some sort using the [express-session](https://www.npmjs.com/package/express-session) module combined with an appropriate session store. This has several disadvantages including the requirement to choose and maintain a session database and extra complexity when working with load balancers. For applications that keep small sessions (e.g. userId, name, and a few permissions) keeping everything in a cookie is more efficient.

This project is based on a fork of [cookie-session](https://github.com/expressjs/cookie-session) heavily modified for compatibility with **passport** 0.6.0 and later.

## Installation

```sh
npm install session-cookie
```

## Example usage

```js
const express = require('express');
const sessionCookie = require('session-cookie');

const app = express();

app.use(sessionCookie({
    name: 'session',
    secret: 'MySecretKey',
    maxAge: 3 * 60 * 60 * 1000 // Three hours
}));
```


Later, when servicing a, store a session variable
```js
req.session.myCustomPermission = true;
```

## API

This section needs to be written. Please contribute at [https://github.com/bredd/session-cookie](https://github.com/bredd/session-cookie)

In the meantime, use the documentation for [cookie-session](https://www.npmjs.com/package/cookie-session) as this module is fully compatible with that API.

## Sample code

This is a complete sample that demonstrates using **session-cookie** with Passport and Google Authentication. It stores the users, ID, name, and email in a digitally-signed session cookie that can be used in later calls. To use it, you must register an OAuth application with Google and place the GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in a .env file.

```js
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
```

