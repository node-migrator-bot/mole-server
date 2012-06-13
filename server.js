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
mkdirp.sync(path.join(commander.store, 'server'));
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

var caCertFile = path.join(commander.store, 'ca-cert.pem');
var serverCertFile = path.join(commander.store, 'crt', 'server-cert.pem');
var serverKeyFile = path.join(commander.store, 'crt', 'server-key.pem');

log.debug('Checking for existing certificates');
if (!path.existsSync(caCertFile)) {
    spawn(path.join(__dirname, 'gen-ca.exp')).on('exit', function (code) {
        spawn(path.join(__dirname, 'gen-user.exp'), [ 'server' ]).on('exit', function (code) {
            log.info('Created CA & server certificates');
            startApp();
        });
    });
} else {
    startApp();
}

function startApp() {
    log.debug('Create HTTP server');
    var app = express.createServer({
        ca: [ fs.readFileSync(caCertFile) ],
        key: fs.readFileSync(serverKeyFile),
        cert: fs.readFileSync(serverCertFile),
        requestCert: true,
    });

    app.get(/\/register\/([0-9a-f-]+)$/, register);
    app.post('/newtoken', newtoken);
    app.post(/\/users\/([a-z0-9_-]+)$/, newuser);
    app.del(/\/users\/([a-z0-9_-]+)$/, deluser);
    app.get('/store', listfiles);
    app.put(/\/store\/([0-9a-z_.-]+)$/, putfile);
    app.get(/\/store\/([0-9a-z_.-]+)$/, getfile);
    app.listen(commander.port);
    log.info('Server listening on port ' + commander.port);
}

function createUserCert(name, callback) {
    var openssl = spawn(path.join(__dirname, 'gen-user.exp'), [ name ]);
    var fingerprint;

    function recv(data) {
        var s = data.toString('utf-8').trim();
        if (s.match(/^[0-9A-F:]+$/)) {
            fingerprint = s;
        } else if (s.length > 0) {
            log.warning(s);
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

    log.debug('Certificate authentication for ' + username + ' succeeded');
    return user;
}

function createUser(name, admin, callback) {
    var user = { created: Date.now(), token: uuid.v4() };

    createUserCert(name, function (fingerprint) {
        user.fingerprint = fingerprint;
        user.admin = !!admin;
        users.set(name, user);
        callback(user);
    });
}

function register(req, res){
    var token = req.params[0];
    var found = false;

    log.debug('GET /register/' + token);
    _.each(users.all(), function (user) {
        if (!found) {
            var name = user.name;
            var ud = user.data;
            if (ud.token === token) {
                found = true;
                var cert = fs.readFileSync('crt/' + name + '-cert.pem', 'utf-8');
                var key = fs.readFileSync('crt/' + name + '-key.pem', 'utf-8');
                delete ud.token;
                ud.registered = Date.now();
                users.save();

                res.json({ cert: cert, key: key });
            }
        }
    });

    if (!found) {
        res.send(404);
        res.end();
    }
}

function newtoken(req, res){
    log.debug('POST /newtoken');
    var user = authenticate(req);
    if (user) {
        user.token = uuid.v4();
        users.save();
        res.json({ token: user.token });
    } else {
        res.send(403);
        res.end();
    };
}

// Create a new user (or reset certificate and token for an existing one).

function newuser(req, res){
    var username = req.params[0];
    log.debug('POST /users/' + username);
    var user = authenticate(req, users);
    if (users.all().length === 0 || user && user.admin) {
        var newUserAdmin = users.all().length == 0;
        createUser(username, newUserAdmin, function (u) {
            res.send(JSON.stringify(u));
        });
    } else {
        res.send(403);
        res.end();
    }
}

// Delete a user

function deluser(req, res){
    var username = req.params[0];
    log.debug('DELETE /users/' + username);
    var user = authenticate(req, users);
    if (user && user.admin) {
        if (users.get(username)) {
            users.del(username);
            users.save();
        } else {
            res.send(404);
        }
    } else {
        res.send(403);
    }
    res.end();
}

// List the files in storage.

function listfiles(req, res) {
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
                res.json(files);
            });
        });
    } else {
        res.send(403);
        res.end();
    }
}

// Add a file to storage.

function putfile(req, res) {
    var file = req.params[0];
    log.debug('PUT /store/' + file);
    var user = authenticate(req);
    if (user) {
        var buffer = '';
        req.setEncoding('utf-8');
        req.on('data', function (chunk) {
            buffer += chunk;
        });
        req.on('end', function () {
            fs.writeFile(path.join('data', file), buffer, function () {
                res.json({ status: 'ok', length: buffer.length });
            });
        });
    } else {
        res.send(403);
        res.end();
    }
}

// Get a file from storage.

function getfile(req, res) {
    var file = req.params[0];
    log.debug('GET /store/' + file);
    var user = authenticate(req);
    if (user) {
        res.sendfile(path.join('data', file));
    } else {
        res.send(403);
        res.end();
    }
}

