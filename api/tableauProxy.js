const crypto = require("crypto");

function base64UrlEncode(str) {
  return Buffer.from(str)
    .toString("base64")
    .replace("+", "-")
    .replace("/", "_")
    .replace(/=+$/, "");
}

function base64UrlDecode(str) {
  str = str.replace("-", "+").replace("_", "/");
  while (str.length % 4) {
    str += "=";
  }
  return Buffer.from(str, "base64").toString();
}

// we store our credentials needed for the creation of the JWT in a.env file.These are actually manually created as enviroment variables on the vercel server we use to host our web app
module.exports = async (req, res) => {
  try {
    const { CLIENT_ID, SECRET_ID, SECRET_VALUE, WURL } = process.env;

    // Read username from request body
    const username = req.body.username || "default_username";

    // Provide headers; This is one of the 3 constituent parts of a JWT
    const header = {
      alg: "HS256",
      typ: "JWT",
      iss: CLIENT_ID,
      kid: SECRET_ID,
    };

    // This means that we're doing base64 encoding which is URL safe which is important for JWTs as they're frequently used as parameters in the URL
    const encodedHeader = base64UrlEncode(JSON.stringify(header));

    // This is essentially creating a random string to be used as an indetifier for each JWT which we create so that feasibly they should not be created more than once in quick succession
    const jti = crypto.randomBytes(16).toString("hex");

    // This is used as a timestamp to say when the JWT should be valid from/to
    const utcNowInSeconds = Math.floor(new Date().getTime() / 1000);

    // This claimset is the bit that makes most of the decisions around who we're authenticating when they can view data and what their scope is.
    const claimSet = {
      sub: username,
      aud: "tableau",
      nbf: utcNowInSeconds - 100,
      jti: jti,
      iss: CLIENT_ID,
      scp: ["tableau:views:embed"],
      exp: utcNowInSeconds + 300,
    };

    // This means that we're doing base64 encoding which is URL safe which is important for JWTs as they're frequently used as parameters in the URL
    const encodedClaimSet = base64UrlEncode(JSON.stringify(claimSet));

    // Here we're creating the signature for the JWT, the 3rd constituent part. Again we're encoding it (manually this time to show we can I guess) and we're applying some cryptography here making a HMAC which is a message authentication code involving a hash function and our secret key. This is obviously very important for security.
    const signatureInput = `${encodedHeader}.${encodedClaimSet}`;
    const signature = crypto
      .createHmac("sha256", SECRET_VALUE)
      .update(signatureInput)
      .digest("base64")
      .replace("+", "-")
      .replace("/", "_")
      .replace(/=+$/, "");

    // We now create the JWT from the 3 different constructed parts
    const jwt = `${encodedHeader}.${encodedClaimSet}.${signature}`;

    //We log the JWT to the console, this is purely for testing/demo purposes and should not be done in production instances
    console.log("Final JWT:", jwt);

    // This is the workbook URL which is the viz we're ultimately going to display. This is returned outside of the function along with the signed JWT
    const wurl = WURL;

    return res.json({ jwt, wurl });
  } catch (error) {
    console.error("An error occurred:", error);
    return res.status(500).json({ error: "An error occurred." });
  }
};
