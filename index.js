const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

app.get('/login', (req, res) => {
    const user = {
        username: 'rohit'
    }
    jwt.sign({user}, 'rohitpanjwani', (err, token) => {
        res.json({
            status: true,
            token
        });
    })
});  

// app.get('/isLoggedIn', verifytoken, (req, res) => {
//     jwt.verify(req.token, 'rohitpanjwani', (err, palyload) => {
//         if (err) {
//             res.sendStatus(403);
//         } else {
//             res.sendStatus(200);
//         }
//     })
// })

app.get('/todos', verifytoken, (req, res) => {
    console.log(res.locals.user)
    res.json({
        status: true,
        todos: []
    });
});

app.post('/todos', verifytoken, (req, res) => {
    res.json({
        status: true
    });
});

function verifytoken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (bearerHeader) {
        const token = bearerHeader.split(' ')[1];
        jwt.verify(token, 'rohitpanjwani', (err, payload) => {
            if (err) {
                res.sendStatus(403);
            } else {
                res.locals.user = payload.user
                next();
            }
        })
    } else {
        res.sendStatus(403);
    }
}

app.listen(8000, () => {
    console.log('listening on port 8000');
})