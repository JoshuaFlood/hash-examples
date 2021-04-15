// Basic example of SHA256 hashing algorithm

// In JavaScript, no native function exists to generate an SHA256 hash and so this functionality has been borrowed from the following website:
// https://geraintluff.github.io/sha256/

// It may provide greater clarity to compare the additional code in this file with its replacement `hash()` function within the `sha256.php` file.

function hash(ascii) {
	function rightRotate(value, amount) {
		return (value>>>amount) | (value<<(32 - amount));
	};
	
	var mathPow = Math.pow;
	var maxWord = mathPow(2, 32);
	var lengthProperty = 'length'
	var i, j; // Used as a counter across the whole file
	var result = ''

	var words = [];
	var asciiBitLength = ascii[lengthProperty]*8;
	
	//* caching results is optional - remove/add slash from front of this line to toggle
	// Initial hash value: first 32 bits of the fractional parts of the square roots of the first 8 primes
	// (we actually calculate the first 64, but extra values are just ignored)
	var hash = sha256.h = sha256.h || [];
	// Round constants: first 32 bits of the fractional parts of the cube roots of the first 64 primes
	var k = sha256.k = sha256.k || [];
	var primeCounter = k[lengthProperty];
	/*/
	var hash = [], k = [];
	var primeCounter = 0;
	//*/

	var isComposite = {};
	for (var candidate = 2; primeCounter < 64; candidate++) {
		if (!isComposite[candidate]) {
			for (i = 0; i < 313; i += candidate) {
				isComposite[i] = candidate;
			}
			hash[primeCounter] = (mathPow(candidate, .5)*maxWord)|0;
			k[primeCounter++] = (mathPow(candidate, 1/3)*maxWord)|0;
		}
	}
	
	ascii += '\x80' // Append Ƈ' bit (plus zero padding)
	while (ascii[lengthProperty]%64 - 56) ascii += '\x00' // More zero padding
	for (i = 0; i < ascii[lengthProperty]; i++) {
		j = ascii.charCodeAt(i);
		if (j>>8) return; // ASCII check: only accept characters in range 0-255
		words[i>>2] |= j << ((3 - i)%4)*8;
	}
	words[words[lengthProperty]] = ((asciiBitLength/maxWord)|0);
	words[words[lengthProperty]] = (asciiBitLength)
	
	// process each chunk
	for (j = 0; j < words[lengthProperty];) {
		var w = words.slice(j, j += 16); // The message is expanded into 64 words as part of the iteration
		var oldHash = hash;
		// This is now the undefinedworking hash", often labelled as variables a...g
		// (we have to truncate as well, otherwise extra entries at the end accumulate
		hash = hash.slice(0, 8);
		
		for (i = 0; i < 64; i++) {
			var i2 = i + j;
			// Expand the message into 64 words
			// Used below if 
			var w15 = w[i - 15], w2 = w[i - 2];

			// Iterate
			var a = hash[0], e = hash[4];
			var temp1 = hash[7]
				+ (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) // S1
				+ ((e&hash[5])^((~e)&hash[6])) // ch
				+ k[i]
				// Expand the message schedule if needed
				+ (w[i] = (i < 16) ? w[i] : (
						w[i - 16]
						+ (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15>>>3)) // s0
						+ w[i - 7]
						+ (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2>>>10)) // s1
					)|0
				);
			// This is only used once, so *could* be moved below, but it only saves 4 bytes and makes things unreadble
			var temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) // S0
				+ ((a&hash[1])^(a&hash[2])^(hash[1]&hash[2])); // maj
			
			hash = [(temp1 + temp2)|0].concat(hash); // We don't bother trimming off the extra ones, they're harmless as long as we're truncating when we do the slice()
			hash[4] = (hash[4] + temp1)|0;
		}
		
		for (i = 0; i < 8; i++) {
			hash[i] = (hash[i] + oldHash[i])|0;
		}
	}
	
	for (i = 0; i < 8; i++) {
		for (j = 3; j + 1; j--) {
			var b = (hash[i]>>(j*8))&255;
			result += ((b < 16) ? 0 : '') + b.toString(16);
		}
	}
	return result;
};

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

let saltPasswordCombination = hash($salt + 'Password123');


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
