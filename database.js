const admin = require('firebase-admin');
const serviceAccount = require('./serviceAccountKey.json'); // from Firebase console

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://scamester-65945-default-rtdb.asia-southeast1.firebasedatabase.app/"
});
const db = admin.database();

module.exports = db;