const bcrypt = require("bcrypt");

const users = [];

(async () => {
  const hashedPassword = await bcrypt.hash("test1234", 10);
  users.push({
    id: "1",
    email: "test@example.com",
    password: hashedPassword
  });
})();

module.exports = users;
