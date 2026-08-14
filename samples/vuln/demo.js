const { exec } = require('child_process');
function run(cmd) {
  exec(cmd, cb => {});
  eval("console.log(" + cmd + ")");
}
var user = 'x" OR 1=1 --';
db.query("SELECT * FROM t WHERE name = '" + user + "'");
document.cookie = "sid=abc";