const bcrypt = require("bcrypt");
const Database = require("better-sqlite3");
const path = require("path");
const readline = require("readline");

const db = new Database(path.join(__dirname, "secureweb.db"));
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

rl.question("Enter your new password: ", async (password) => {
  try {
    if (
      password.length < 8 ||
      Buffer.byteLength(password, "utf8") > 72
    ) {
      throw new Error("Password must be 8-72 bytes.");
    }

    const admin = db.prepare(
      "SELECT id, username FROM users WHERE username = ? COLLATE NOCASE AND role = 'admin'"
    ).get("ArafaAdmin");

    if (!admin) throw new Error("Admin account not found.");

    const hash = await bcrypt.hash(password, 12);

    db.prepare(
      "UPDATE users SET password_hash = ? WHERE id = ? AND role = 'admin'"
    ).run(hash, admin.id);

    console.log("SUCCESS: Admin password changed.");
  } catch (error) {
    console.error("ERROR:", error.message);
  } finally {
    rl.close();
    db.close();
  }
});
