const fs = require('fs');
const bodyParser = require('body-parser');
const jsonServer = require('json-server');
const jwt = require('jsonwebtoken');

const server = jsonServer.create();
const router = jsonServer.router('./database.json');
const userdb = JSON.parse(fs.readFileSync('./users.json', 'utf-8'));

server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = '72676376';

const expiresIn = '1h';

function createToken(payload) {
    return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
    return jwt.verify(token, SECRET_KEY, (err, decode) =>
        decode !== undefined ? decode : err
    );
}

function credentialsAreCorrect({ email, password }) {
    return (
        userdb.users.findIndex(
            user => user.email === email && user.password === password
        ) !== -1
    );
}

function emailIsAlreadyRegistered({ email }) {
    return userdb.users.findIndex(user => user.email === email) !== -1;
}

server.post('/auth/register', (req, res) => {
    const { email, password } = req.body;
    if (emailIsAlreadyRegistered({ email })) {
        const status = 401;
        const message = 'Email already exists';
        res.status(status).json({ status, message });
        return;
    }

    fs.readFile('./users.json', (err, data) => {
        if (err) {
            const status = 401;
            const message = err;
            res.status(status).json({ status, message });
            return;
        }
        data = JSON.parse(data.toString());

        let last_item_id = data.users[data.users.length - 1].id;

        data.users.push({
            id: last_item_id + 1,
            email: email,
            password: password,
        });
        // let writeData =
        fs.writeFile('./users.json', JSON.stringify(data), (err, result) => {
            if (err) {
                const status = 401;
                const message = err;
                res.status(status).json({ status, message });
                return;
            }
        });
    });
    const access_token = createToken({ email, password });
    res.status(200).json({ access_token });
});

server.post('/auth/login', (req, res) => {
    const { email, password } = req.body;

    if (!credentialsAreCorrect({ email, password })) {
        const status = 401;
        const message = 'Incorrect Email or Password';
        res.status(status).json({ status, message });
        return;
    }
    const access_token = createToken({ email, password });
    res.status(200).json({ access_token });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
    if (
        req.headers.authorization === undefined ||
        req.headers.authorization.split(' ')[0] !== 'Bearer'
    ) {
        const status = 401;
        const message = 'Error in authorization format';
        res.status(status).json({ status, message });
        return;
    }
    try {
        let verifyTokenResult;
        verifyTokenResult = verifyToken(
            req.headers.authorization.split(' ')[1]
        );

        if (verifyTokenResult instanceof Error) {
            const status = 401;
            const message = 'Access token not provided';
            res.status(status).json({ status, message });
            return;
        }
        next();
    } catch (err) {
        const status = 401;
        const message = 'Error access_token is revoked';
        res.status(status).json({ status, message });
    }
});

server.use(router);

server.listen(5000, () => {
    console.log('Running fake api json server');
});
