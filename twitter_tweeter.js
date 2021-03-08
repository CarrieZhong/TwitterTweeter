const crypto = require('crypto');
const path = require('path');
const express = require('express');
const app = express();
const cookie = require('cookie');
const session = require('express-session');
const bodyParser = require('body-parser');
const server = require('http').createServer(app);

const PORT = 3000;
const COOKIE_DURATION = 60 * 60 * 24 * 7;  // number of seconds in one week

app.use(bodyParser.json());

let Datastore = require('nedb');
let users = new Datastore({ filename: 'db/users.db', autoload: true, timestampData: true });
let tweets = new Datastore({ filename: 'db/tweets.db', autoload: true, timestampData: true });
let messages = new Datastore({ filename: 'db/messages.db', autoload: true, timestampData: true });

let Tweet = function item(content, username) {
    this.content = content;
    this.username = username;
}

let Message = function item(from, to, message) {
    this.from = from;
    this.to = to;
    this.message = message;
}

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

// curl -H "Content-Type: application/json" -X POST -d '{"username":"alice123","password":"alice","displayName": "Alice"}' -c cookie.txt localhost:3000/signup/
app.post('/signup/', function (req, res, next) {
    let username = req.body.username;
    let password = req.body.password;
    let displayName = req.body.displayName;

    users.findOne({ _id: username }, function (err, user) {
        if (err) return res.status(500).end(err);
        if (user) return res.status(409).end("username " + username + " already exists");  // don't allow two accounts w/same username

        // save password as salted hash
        let salt = crypto.randomBytes(16).toString('base64');
        let hash = crypto.createHmac('sha512', salt);
        hash.update(password);
        let saltedHash = hash.digest('base64');

        users.update({ _id: username }, { _id: username, displayName: displayName, salt: salt, saltedHash: saltedHash }, { upsert: true }, function (err) {
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

// curl localhost:3000/api/users/
app.get('/api/users/', function (req, res, next) {
    // show the usernames and display names of all users, sorted in alphabetical order of username
    users.find({}, {_id: 1, displayName: 1}).sort({ '_id': 1 }).exec(function (err, allUsers) {
        if (err) return res.status(500).end(err);
        return res.json(allUsers);  // even if there are no users yet
    });
});

// curl localhost:3000/api/users/:Alice
app.get('/api/users/:name/', function (req, res, next) {
    // show username and display name of all users who share the given display name
    users.find({ displayName: req.params.name }, { _id: 1, displayName: 1 }, function (err, searchedUsers) {
        if (err) return res.status(500).end(err);
        return res.json(searchedUsers);  // even if no accounts with the given display name are found
    });
});

// curl -b cookie.txt -H "Content-Type: application/json" -X POST -d '{"content":"hello world!"}' localhost:3000/api/tweets/
app.post('/api/tweets/', isAuthenticated, function (req, res, next) {  // requires being signed in
    // post a new tweet under the username of whoever is signed in
    let tweet = new Tweet(req.body.content, req.session.username);
    tweets.insert(tweet, function (err, tweet) {
        if (err) return res.status(500).end(err);
        return res.json(tweet);
    });
});

// curl -b cookie.txt -H "Content-Type: application/json" -X PATCH -d '{"content":"hello again"}' localhost:3000/api/tweets/kSInsV1SffDgcfWk/
app.patch('/api/tweets/:id/', isAuthenticated, function (req, res, next) {
    // update the tweet with the given id
    tweets.findOne({ _id: req.params.id }, function (err, searchedTweet) {
        if (err) return res.status(500).end(err);
        if (!searchedTweet) return res.status(404).end("Tweet id #" + req.params.id + " does not exist");  // can't update a nonexistent tweet
        if (searchedTweet.username != req.session.username) return res.status(403).end("forbidden");  // can't update another user's tweet
        tweets.update({ _id: req.params.id }, { $set: { content: req.body.content } }, function (err, num) {
            if (err) return res.status(500).end(err);
            res.json(req.params.id);
        });
    });
});

// curl -b cookie.txt -X DELETE localhost:3000/api/tweets/kSInsV1SffDgcfWk/
app.delete('/api/tweets/:id/', isAuthenticated, function (req, res, next) {
    // delete the tweet with the given id
    tweets.findOne({ _id: req.params.id }, function (err, searchedTweet) {
        if (err) return res.status(500).end(err);
        if (!searchedTweet) return res.status(404).end("Tweet id #" + req.params.id + " does not exist");  // can't delete a nonexistent tweet
        if (searchedTweet.username != req.session.username) return res.status(403).end("forbidden");  // can't delete another user's tweet
        tweets.remove({ _id: searchedTweet._id }, function (err, num) {
            tweets.persistence.compactDatafile();
            if (err) return res.status(500).end(err);
            res.json(req.params.id);
        });
    });
});

// curl localhost:3000/api/tweets/
app.get('/api/tweets/', function (req, res, next) {
    // show all tweets sorted by time creation
    tweets.find({}).sort({ createdAt: -1 }).exec(function (err, allTweets) {
        if (err) return res.status(500).end(err);
        return res.json(allTweets);  // even if there are no tweets yet
    });
});

// curl localhost:3000/api/tweets/alice123
app.get('/api/tweets/:username/', function (req, res, next) {
    // show all tweets posted by a given user
    tweets.find({ username: req.params.username }, function (err, searchedTweets) {
        if (err) return res.status(500).end(err);
        if (!searchedTweets) return res.status(404).end("User:" + req.params.username + " does not exist");
        return res.json(searchedTweets);  // even if that user hasn't made any tweets yet
    });
});

// post a message to someone
app.post('/api/messages/:username/', isAuthenticated, function (req, res, next) {  // requires being signed in
    // send a new message from singed in user to someone else
    let msg = new Message(req.session.username, req.params.username, req.body.content);
    messages.insert(Message, function (err, msg) {
        if (err) return res.status(500).end(err);
        return res.json(msg);
    });
});

// get messages sent between current user and someone
app.get('/api/messages/:username/', function (req, res, next) {
    // show all tweets posted by a given user
    messages.find({ from: req.session.username, to: req.params.username }, function (err, messages) {
        if (err) return res.status(500).end(err);
        if (!messages) return res.status(404).end("User:" + req.params.username + " has no messages with you");
        return res.json(messages); 
    }).sort({ postedAt: -1 });
});


server.listen(PORT, function (err) {
    if (err) console.log(err);
    else console.log("HTTP server on http://localhost:%s", PORT);
});
