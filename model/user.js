let users = [];
let nextId = 1;

class User {
  constructor(email, password) {
    this.id = nextId++;
    this.email = email;
    // default: plain
    this.password = password; 
  }
}

module.exports = { users, User };