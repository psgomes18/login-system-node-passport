const express = require('express');
const session = require('express-session');
const hbs = require('express-handlebars');
const mongoose = require('mongoose')
const passport = require('passport');
const localStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')
const app = express()

/*mongoose.connect("mongodb://localhost:27017/pauloteste", {
    useNewUrlParser: true,
    useUnifiedTopology: true
});*/

const UserSchema = new mongoose.Schema({
    username: {
        type: 'String',
        required: true
    },
    password: {
        type: 'String',
        required: true
    }
});

const User = mongoose.model('User', UserSchema);

//Middleware
app.engine('hbs', hbs({
    extname: '.hbs'
}));
app.set('view engine', 'hbs');
app.use(express.static(__dirname + '/public'));
app.use(session({
    secret: 'verygoodsecrety',
    resave: false,
    saveUninitialized: true
}));
app.use(express.urlencoded({
    extend: false
}));
app.use(express.json());

//Passport.js
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (user, done) {
    User.findById(user.id, function (err, user) {
        done(err, user);
    });
});

passport.use(new localStrategy(function (username, password, done) {
    User.findOne({
        username: username
    }, function (err, user) {
        if (err) {
            return done(err);
        }
        if (!user) {
            return done(null, false, {
                message: 'Usuario Incorreto!'
            });
        }

        bcrypt.compare(password, user.password, function (err, res) {
            if (err) {
                return done(err);

                if (res === false) {
                    return done(null, false, {
                        message: 'Senha incorreta!'
                    });

                    return done(null, user);
                };
            };
        });
    });
}));


function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

function isLoggedOut(req, res, next) {
    if (!req.isAuthenticated()) return next();
    res.redirect('/login');
}

//Rotas
app.get('/', isLoggedIn, (req, res) => {
    res.render('index', {
        title: 'home'
    });
});

app.get('/about', isLoggedIn, (req, res) => {
    res.render('index', {
        title: 'About'
    });
});

app.get('/login', isLoggedOut, (req, res) => {
    const response = {
        title: "Login",
        error: req.query.error
    }
    res.render('login', response);
});

app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login?error=true'
}));

//Admin User
app.get('/setup', async (req, res) => {
    const exists = await User.exists({
        username: "admin"
    });

app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

    if (exists) {
        res.redirect('/login');
        return;
    };

    bcrypt.genSalt(10, function (err, salt) {
        if (err) return next(err);
        bcrypt.hash("pass", salt, function (err, hash) {
            if (err) return next(err);
            const newAdmin = new User({
                username: "admin",
                password: hash
            });

            newAdmin.save();
            res.redirect('/login');
        });
    });
});


app.listen(3000, () => {
    console.log('listening on http://localhost:3000')
})