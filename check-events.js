
const Database = require("better-sqlite3");

const db = new Database("./secureweb.db");

const events = db.prepare(`
  SELECT event_type, COUNT(*) AS total
  FROM security_events
  GROUP BY event_type
`).all();

console.table(events);

db.close();
