const crypto = require('crypto');
const path = require('path');
const express = require('express');
const app = express();
const cookie = require('cookie');
const session = require('express-session');
const bodyParser = require('body-parser');
const http = require('http');

const PORT = 3000;
const COOKIE_DURATION = 60 * 60 * 24 * 7;  // number of seconds in one week

app.use(bodyParser.json());

let Datastore = require('nedb');
let users = new Datastore({ filename: 'db/users.db', autoload: true, timestampData: true });

let isAuthenticated = function (req, res, next) {
    if (!req.username) return res.status(401).end("access denied");
    next();
};

app.use(express.static('static'));

app.use(session({
    secret: 'please change this secret',
    resave: false,
    saveUninitialized: true,
}));

app.use(function (req, res, next) { // if signed in session, get the username; otherwise, not signed in session
    req.username = (req.session.username) ? req.session.username : "";
    console.log("HTTP request", req.username, req.method, req.url, req.body);
    next();
});

// curl -H "Content-Type: application/json" -X POST -d '{"username":"alice123","password":"alice","display_name": "Alice"}' -c cookie.txt localhost:3000/signup/
app.post('/signup/', function (req, res, next) {
    let username = req.body.username;
    let password = req.body.password;
    let display_name = req.body.display_name;

    users.findOne({ _id: username }, function (err, user) {
        if (err) return res.status(500).end(err);
        if (user) return res.status(409).end("username " + username + " already exists");  // don't allow two accounts w/same username

        // save password as salted hash
        let salt = crypto.randomBytes(16).toString('base64');
        let hash = crypto.createHmac('sha512', salt);
        hash.update(password);
        let saltedHash = hash.digest('base64');

        users.update({ _id: username }, { _id: username, display_name: display_name, salt: salt, saltedHash: saltedHash }, { upsert: true }, function (err) {
            if (err) return res.status(500).end(err);

            req.session.username = username;  // get signed in when you sign up

            // initialize cookie so we can stay signed in for given amount of time
            res.setHeader('Set-Cookie', cookie.serialize('username', username, {
                path: '/',
                maxAge: COOKIE_DURATION
            }));
            return res.json("user " + username + " signed up");
        });
    });
});

// curl -H "Content-Type: application/json" -X POST -d '{"username":"alice","password":"alice"}' -c cookie.txt localhost:3000/signin/
app.post('/signin/', function (req, res, next) {
    let username = req.body.username;
    let password = req.body.password;
    // retrieve user from the database
    users.findOne({ _id: username }, function (err, user) {
        if (err) return res.status(500).end(err);
        if (!user) return res.status(401).end("access denied");  // an account with this username doesn't exist

        // check pw against the saved salted hash
        let hash = crypto.createHmac('sha512', user.salt);
        hash.update(password);
        let saltedHash = hash.digest('base64');

        if (user.saltedHash !== saltedHash) return res.status(401).end("access denied");  // username exists, but wrong pw
        req.session.username = username;  // o/w, successfully signed in

        // initialize cookie so we can stay signed in for given amount of time
        res.setHeader('Set-Cookie', cookie.serialize('username', username, {
            path: '/',
            maxAge: COOKIE_DURATION
        }));
        return res.json("user " + username + " signed in");
    });
});

// curl -b cookie.txt -c cookie.txt localhost:3000/signout/
app.get('/signout/', function (req, res, next) {
    req.session.destroy();
    res.setHeader('Set-Cookie', cookie.serialize('username', '', {
        path: '/',
        maxAge: COOKIE_DURATION
    }));
    res.redirect('/');
});

http.createServer(app).listen(PORT, function (err) {
    if (err) console.log(err);
    else console.log("HTTP server on http://localhost:%s", PORT);
});
