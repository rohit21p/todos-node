const express = require('express');
const jwt = require('jsonwebtoken');
const mongo = require('mongodb');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const auth = require('basic-auth');

const config = require('./config')

const app = express();
const MongoClient = mongo.MongoClient;

app.use(bodyParser.json())

app.get('/login', connectDatabase, (req, res) => {
    const user = auth(req);
    res.locals.db.collection('users').findOne({
        username: user.name,
    }, (err, result) => {
        if (err) {
            res.sendStatus(400);
            res.locals.dbc.close();
        } else {
            bcrypt.compare(user.pass, result.password, (err, match) => {
                if (match) {
                    jwt.sign({username: user.name}, config.JWT_SECRET, (err, token) => {
                        if (err) {
                            res.sendStatus(400);
                            res.locals.dbc.close();
                        } else {
                            res.locals.dbc.close();
                            res.json({
                                token
                            })
                        }
                    })
                } else {
                    res.sendStatus(400);
                    res.locals.dbc.close();
                }
            })
        }
    })
}); 

app.post('/signup', connectDatabase, (req, res) => {
    bcrypt.hash(req.body.password, 10, (err, hash) => {
        if (err) {
            res.sendStatus(400);
            res.locals.dbc.close();
        } else {
            res.locals.db.collection('users').insertOne({
                username: req.body.username,
                password: hash,
                createdAt: new Date()
            }, (err, status) => {
                if (err) {
                    if (err.code === 11000) {
                        res.locals.dbc.close();
                        res.status(400).json({
                            err: 'User Already Exists'
                        })
                    } else {
                        res.sendStatus(400);
                        res.locals.dbc.close();
                    }
                } else {
                    res.sendStatus(200);
                    res.locals.dbc.close();
                }
            })
        }
    });
}); 

app.get('/todos', verifytoken, connectDatabase, (req, res) => {
    res.locals.db.collection('todos').find({
        username: res.locals.user
    }, (err, result) => {
        if (err) {
            res.sendStatus(403);
            res.locals.dbc.close();
        } else {
            result.toArray((err, data) => {
                res.locals.dbc.close();
                res.json({
                    data
                })
            })
        }
    })
});

app.post('/todos', verifytoken, connectDatabase, (req, res) => {
    res.locals.db.collection('todos').insertOne({
        ...req.body,
        username: res.locals.user,
        createdAt: new Date()
    }, (err, result) => {
        if (err) {
            res.sendStatus(403);
            res.locals.dbc.close();
        } else {
            res.sendStatus(200)
            res.locals.dbc.close();
        }
    })
});


app.delete('/todos', verifytoken, connectDatabase, (req, res) => {
    res.locals.db.collection('todos').deleteOne({
        _id: mongo.ObjectID(req.body.id)
    }, (err, result) => {
        if (err) {
            res.sendStatus(403);
            res.locals.dbc.close();
        } else {
            res.sendStatus(200)
            res.locals.dbc.close();
        }
    })
});

function verifytoken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (bearerHeader) {
        const token = bearerHeader.split(' ')[1];
        jwt.verify(token, config.JWT_SECRET, (err, payload) => {
            if (err) {
                res.sendStatus(403);
            } else {
                res.locals.user = payload.username
                next();
            }
        })
    } else {
        res.sendStatus(403);
    }
}

function connectDatabase(req, res, next) {
    MongoClient.connect(config.MONGO_LOCAL_URI, (err, dbc) => {
        if(err) {
            res.sendStatus(400);
        } else {
            res.locals.db = dbc.db('todos');
            res.locals.dbc = dbc;
            next();
        }
    })
}

module.exports = app;