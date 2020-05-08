const fs = require("fs");

const jwt = require("jsonwebtoken");

const privateKey = fs.readFileSync("private.pem");
const token = jwt.sign(
  {
    "email": "user@example.com",
    "type": "app",
    "identity_nonce": "NONCE1",
  },
  privateKey,
  {
    algorithm: "RS256",
    audience: [
      "AUDIENCE1",
    ],
    expiresIn: "36500 days",
    header: {
      kid: "key1",
    },
    issuer: "https://example.cloudflareaccess.com",
    notBefore: 0,
    subject: "SUBJECT1",
  },
);
console.log(token);
