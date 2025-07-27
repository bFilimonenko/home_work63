const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const flash = require('express-flash');

const app = express();
const PORT = 3005;

app.use(flash());

const users = [];

app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

app.use(session({
  secret: 'yourSecretKey',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false
  }
}));

app.use((req, res, next) => {
  res.locals.success = req.flash('success');
  res.locals.error = req.flash('error');
  next();
});


app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');

passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, (email, password, done) => {
  const user = users.find(u => u.email === email);
  if (!user) {
    return done(null, false, { message: 'User not found. Please register' });
  }

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) return done(err);
    if (!isMatch) {
      return done(null, false, { message: 'Invalid password' });
    }
    return done(null, user);
  });
}));


passport.serializeUser((user, done) => done(null, user.email));
passport.deserializeUser((email, done) => {
  const user = users.find(u => u.email === email);
  done(null, user);
});

app.get('/', (req, res) => {
  res.render('index', { user: req.user });
});

app.get('/register', (req, res) => res.render('register'));
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, password: hashed });
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { error: req.flash('error') });
});
app.post('/login',
  passport.authenticate('local', {
    successRedirect: '/protected',
    failureRedirect: '/login',
    failureFlash: true
  }));

app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

const ensureAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
};

app.get('/protected', ensureAuthenticated, (req, res) => {
  res.render('protected', { user: req.user });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
