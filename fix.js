const fs = require('fs');
let c = fs.readFileSync('backend/scanner/detectionEngine.js', 'utf8');
c = c.replace(/\\`/g, '`').replace(/\\\$/g, '$');
c = c.replace(/\\\\/g, '\\');
fs.writeFileSync('backend/scanner/detectionEngine.js', c);
console.log('Fixed');
