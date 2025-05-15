/**
 * Encrypts a payload into a JWT token with additional encryption
 * @param {Object} payload - The data to be encrypted
 * @returns {String} - The encrypted JWT token
 */
const encrypt = (payload) => {
  // Secret key for JWT signing
  const jwtSecret = "your_jwt_secret_key";

  // Secret key for encryption (should be 32 characters for AES-256)
  const encryptionKey = "this_is_a_32_char_encryption_key!!";

  // Step 1: Create a JWT token
  // Note: In a browser environment, we're using the jwt-decode library
  const header = {
    alg: "HS256",
    typ: "JWT"
  };

  // Base64 encode the header and payload
  const base64Header = btoa(JSON.stringify(header));
  const base64Payload = btoa(JSON.stringify(payload));

  // Create the JWT content (without signature yet)
  const jwtContent = `${base64Header}.${base64Payload}`;

  // Create signature using HMAC SHA-256
  const signature = CryptoJS.HmacSHA256(jwtContent, jwtSecret).toString(CryptoJS.enc.Base64);

  // Create the complete JWT token
  const jwtToken = `${jwtContent}.${signature}`;

  // Step 2: Encrypt the JWT token using AES
  const encrypted = CryptoJS.AES.encrypt(jwtToken, encryptionKey).toString();

  return encrypted;
};

/**
 * Decrypts an encrypted JWT token and returns the original payload
 * @param {String} token - The encrypted JWT token
 * @returns {Object} - The decrypted payload
 */
const decrypt = (token) => {
  // Secret key for encryption (should be 32 characters for AES-256)
  const encryptionKey = "this_is_a_32_char_encryption_key!!";

  // Step 1: Decrypt the token using AES
  const decryptedBytes = CryptoJS.AES.decrypt(token, encryptionKey);
  const jwtToken = decryptedBytes.toString(CryptoJS.enc.Utf8);

  // Step 2: Split the JWT token into its components
  const [base64Header, base64Payload, signature] = jwtToken.split('.');

  // Step 3: Decode the payload
  const payload = JSON.parse(atob(base64Payload));

  return payload;
};

// For browser compatibility
window.module = {};
module.exports = {
  encrypt,
  decrypt
};
