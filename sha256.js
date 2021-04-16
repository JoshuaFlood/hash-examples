// Basic example of SHA256 hashing algorithm

// In JavaScript, no native function exists to generate an SHA256 hash and so the following function has been sourced for this purpose:
/**
* Secure Hash Algorithm (SHA256)
* http://www.webtoolkit.info/
* Original code by Angel Marin, Paul Johnston
**/

function SHA256(s){
 var chrsz = 8;
 var hexcase = 0;

 function safe_add (x, y) {
 var lsw = (x & 0xFFFF) + (y & 0xFFFF);
 var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
 return (msw << 16) | (lsw & 0xFFFF);
 }

 function S (X, n) { return ( X >>> n ) | (X << (32 - n)); }
 function R (X, n) { return ( X >>> n ); }
 function Ch(x, y, z) { return ((x & y) ^ ((~x) & z)); }
 function Maj(x, y, z) { return ((x & y) ^ (x & z) ^ (y & z)); }
 function Sigma0256(x) { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
 function Sigma1256(x) { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
 function Gamma0256(x) { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
 function Gamma1256(x) { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }

 function core_sha256 (m, l) {
 var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
 var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
 var W = new Array(64);
 var a, b, c, d, e, f, g, h, i, j;
 var T1, T2;

 m[l >> 5] |= 0x80 << (24 - l % 32);
 m[((l + 64 >> 9) << 4) + 15] = l;

 for ( var i = 0; i<m.length; i+=16 ) {
 a = HASH[0];
 b = HASH[1];
 c = HASH[2];
 d = HASH[3];
 e = HASH[4];
 f = HASH[5];
 g = HASH[6];
 h = HASH[7];

 for ( var j = 0; j<64; j++) {
 if (j < 16) W[j] = m[j + i];
 else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);

 T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
 T2 = safe_add(Sigma0256(a), Maj(a, b, c));

 h = g;
 g = f;
 f = e;
 e = safe_add(d, T1);
 d = c;
 c = b;
 b = a;
 a = safe_add(T1, T2);
 }

 HASH[0] = safe_add(a, HASH[0]);
 HASH[1] = safe_add(b, HASH[1]);
 HASH[2] = safe_add(c, HASH[2]);
 HASH[3] = safe_add(d, HASH[3]);
 HASH[4] = safe_add(e, HASH[4]);
 HASH[5] = safe_add(f, HASH[5]);
 HASH[6] = safe_add(g, HASH[6]);
 HASH[7] = safe_add(h, HASH[7]);
 }
 return HASH;
 }

 function str2binb (str) {
 var bin = Array();
 var mask = (1 << chrsz) - 1;
 for(var i = 0; i < str.length * chrsz; i += chrsz) {
 bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i % 32);
 }
 return bin;
 }

 function Utf8Encode(string) {
 string = string.replace(/\r\n/g,'\n');
 var utftext = '';

 for (var n = 0; n < string.length; n++) {

 var c = string.charCodeAt(n);

 if (c < 128) {
 utftext += String.fromCharCode(c);
 }
 else if((c > 127) && (c < 2048)) {
 utftext += String.fromCharCode((c >> 6) | 192);
 utftext += String.fromCharCode((c & 63) | 128);
 }
 else {
 utftext += String.fromCharCode((c >> 12) | 224);
 utftext += String.fromCharCode(((c >> 6) & 63) | 128);
 utftext += String.fromCharCode((c & 63) | 128);
 }

 }

 return utftext;
 }

 function binb2hex (binarray) {
 var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef';
 var str = '';
 for(var i = 0; i < binarray.length * 4; i++) {
 str += hex_tab.charAt((binarray[i>>2] >> ((3 - i % 4)*8+4)) & 0xF) +
 hex_tab.charAt((binarray[i>>2] >> ((3 - i % 4)*8 )) & 0xF);
 }
 return str;
 }

 s = Utf8Encode(s);
 return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
}

///
// Generating a salt
///

// In this scenario, our aim is to create a secure hash from the user's password.

// Working with large numbers of users, it is likely that some share the same password, username etc. and so creating a hash solely using any
// of these strings would not provide a great deal of security.

// To solve this problem, we create what is known as a 'salt'.
// The salt is a string which is unique to the user and/or application, but which does not contain any sensitive information such as a password or username.
// In addition to being unique, the salt should also be of length equal to or greater than the output. For this example we will create an sha256 hash,
// so the salt should be at least 256 bits long.

// We can create a pseudo-random string that is 256 characters long, however there is no way to ensure that this string will be unique.

// In order to solve this problem, I have migrated the PHP code from the following article:
// https://www.w3docs.com/snippets/php/how-to-generate-a-random-string-with-php.html
// Note that an additional `rand()` function was created as a substitute for the native PHP function discussed in the article.
// This function generates a random whole number between two given numbers. This is not cryptographically secure and offers no measure of security in itself.

function rand(min, max) {
  var min = min || 0,
      max = max || 2048;

  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function getRandomString(n) {
    let characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let randomString = '';
  
    for (let i = 0; i < n; i++) {
        let index = rand(0, characters.length - 1);
        randomString += characters[index];
    }
  
    return randomString;
}

// To finally create our salt, we call the `now()` method on Javascript's built-in `Date` object to grab the current UNIX timestamp and then append a random, 256-bit string to it.

let salt = Date.now() + getRandomString(256);


///
// Generating a hash
///

// Once we have our salt, we attach it as a prefix to the user's password and pass it as a parameter to the `hash()` function.
// Unlike the PHP example stored in this repo, the `hash()` function takes only one argument.
// If you would like me to include examples of other algorithms then please let me know which algorithms
// you would like to implement in the 'issues' section of this repository.

let saltPasswordCombination = SHA256($salt + 'Password123');


///
// Additional notes
///

// It is important to remember that this code should only ever be executed client-side, and the user's password should never be transmitted over the internet.

// In a production environment, the salt would only be generated when a user creates a new account.
// The salt would then be stored in a database alongside their username and the value of the `saltPasswordCombination` variable above,
// but the database would not store the user's password.

// Whenever an existing user attempts to login to the site, the client makes a request to the server and retrieves the salt from the database.
// The client executes the `hash()` function, using the salt from the database in place of the `salt` variable in the above example.
// The resulting hash is then sent back to the server where it is compared against the hash that was stored in the database when the user created their account.
// If both hashes are the same, then the user must have provided the correct password and is allowed access to the site.
// If the hashes are not the same, then the user must have provided an incorrect password and is not granted access to the site.

// If a user wishes to change their password, a new value is generated using the same salt and the new password and the resulting hash replaces the
// hash that was previously stored in the database, to be compared against future login attempts.
