const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const users = require("./users");

function initialize(passport) {
  const authenticateUser = async (email, password, done) => {
    const user = users.find((user) => user.email === email);
    if (!user) return done(null, false, { message: "Користувача не знайдено" });

    try {
      if (await bcrypt.compare(password, user.password)) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Невірний пароль" });
      }
    } catch (err) {
      return done(err);
    }
  };

  passport.use(new LocalStrategy({ usernameField: "email" }, authenticateUser));

  passport.serializeUser((user, done) => done(null, user.id));

  passport.deserializeUser((id, done) => {
    const user = users.find((user) => user.id === id);
    return done(null, user);
  });
}

module.exports = initialize;
