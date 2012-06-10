#!/usr/bin/env node

var _ = require('underscore')._;
var async = require('async');
var commander = require('commander');
var express = require('express')
var fs = require('fs');
var https = require('https');
var log = require('winston');
var path = require('path');
var spawn = require('child_process').spawn;
var uuid = require('node-uuid');
var mkdirp = require('mkdirp');

// Set up configuration

commander
    .option('-p, --port <port>', 'set the listen port (9443)', 9443)
    .option('-s, --store <store>', 'set the store directory (~/mole-store)', path.join(process.env['HOME'], 'mole-store'))
    .option('-d, --debug', 'show debug output', false)
    .parse(process.argv);

// Set up the storage directory and move there

mkdirp.sync(path.join(commander.store, 'crt'));
mkdirp.sync(path.join(commander.store, 'data'));
process.chdir(commander.store);

// Set up logging

log.setLevels(log.config.syslog.levels);
log.remove(log.transports.Console);
log.add(log.transports.Console, {level: commander.debug ? 'debug' : 'info', timestamp: true});

// Set up users

var userStore = require('./lib/users');
var userFile = path.join(commander.sore, 'users.json');
log.debug('Using users file', userFile);
var users = new userStore(userFile);

log.debug('Create HTTP server');
var app = express.createServer({
    ca: [ fs.readFileSync(path.join(__dirname, 'ca-cert.pem')) ],
    key: fs.readFileSync(path.join(__dirname, 'crt/server-key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'crt/server-cert.pem')),
    requestCert: true,
});

function createUserCert(name, callback) {
    var openssl = spawn(path.join(__dirname, 'gen-user.exp'), [ __dirname, name ]);
    var fingerprint;

    function recv(data) {
        var s = data.toString('utf-8').trim();
        if (s.match(/^[0-9A-F:]+$/)) {
            fingerprint = s;
        } else {
            log.warning(data);
        }
    }

    openssl.stdout.on('data', recv);
    openssl.stderr.on('data', recv);

    openssl.on('exit', function (code) {
        callback(fingerprint);
    });
}

function authenticate(req) {
    if (!req.client.authorized) {
        log.debug('Client not authorized');
        return null;
    }

    var cert = req.connection.getPeerCertificate();
    var username = cert.subject.CN;

    var user = users.get(username);
    if (!user) {
        log.warning('Certificate claimed username "' + username + '" which does not exist');
        return null;
    }

    if (user.fingerprint !== cert.fingerprint) {
        log.warning('Certificate presented for "' + username + '" does not match stored fingerprint');
        return null;
    }

    log.info('Certificate authentication for ' + username + ' succeeded');
    return user;
}

function createUser(name, callback) {
    var user = { created: Date.now(), token: uuid.v4() };

    createUserCert(name, function (fingerprint) {
        user.fingerprint = fingerprint;
        users.set(name, user);
        callback(user);
    });
}

app.get('/register/:token', function(req, res){
    log.debug('GET /register/' + req.params.token);
    _.each(users.all(), function (user) {
        var name = user.name;
        var ud = user.data;
        if (ud.token === req.params.token) {
            var cert = fs.readFileSync('crt/' + name + '-cert.pem', 'utf-8');
            var key = fs.readFileSync('crt/' + name + '-key.pem', 'utf-8');
            res.contentType('json');
            res.send(JSON.stringify({ cert: cert, key: key }));
            delete ud.token;
            ud.registered = Date.now();
            users.save();
        }
    });
    res.end();
});

app.post('/newtoken', function(req, res){
    log.debug('POST /newtoken');
    var user = authenticate(req);
    if (user) {
        user.token = uuid.v4();
        users.save();
        res.contentType('json');
        res.send(JSON.stringify({ token: user.token }));
    };
    res.end();
});

// Create a new user (or reset certificate and token for an existing one).

app.post('/users/:username', function(req, res){
    log.debug('POST /users/' + req.params.username);
    var user = authenticate(req, users);
    if (users.all().length === 0 // There are no users yet
        || user && user.admin) { // The authenticated user is an admin.
        createUser(req.params.username, function (u) {
            res.contentType('json');
            res.send(JSON.stringify(u));
            res.end();
        });
    } else {
        res.end();
    }
});

// List the files in storage.

app.get('/store', function (req, res) {
    log.debug('GET /store');
    function stat(fname, callback) {
        fs.stat(path.join('data', fname), function (err, res) {
            if (err) {
                callback(err);
            } else {
                callback(null, { name: fname, mtime: res.mtime.getTime() });
            }
        });
    }

    var user = authenticate(req);
    if (user) {
        fs.readdir(path.join(commander.store, 'data'), function (err, files) {
            async.map(files, stat, function (err, files) {
                res.contentType('json');
                res.send(JSON.stringify(files));
                res.end();
            });
        });
    } else {
        res.end();
    }
});

// Add a file to storage.

app.put('/store/:file', function (req, res) {
    log.debug('PUT /store/' + req.params.file);
    var user = authenticate(req);
    if (user) {
        var buffer = '';
        req.setEncoding('utf-8');
        req.on('data', function (chunk) {
            buffer += chunk;
        });
        req.on('end', function () {
            fs.writeFile(path.join('data', req.params.file), buffer, function () {
                res.contentType('json');
                res.send(JSON.stringify({ status: 'ok', length: buffer.length }));
                res.end();
            });
        });
    } else {
        res.end();
    }
});

// Get a file from storage.

app.get('/store/:file', function (req, res) {
    log.debug('GET /store/' + req.params.file);
    var user = authenticate(req);
    if (user) {
        res.sendfile(path.join('data', req.params.file));
    } else {
        res.end();
    }
});

// Start the HTTPS server.

app.listen(commander.port);
log.debug('Server listening on port ' + commander.port);
