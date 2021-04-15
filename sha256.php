<?php

// Basic example of SHA256 hashing algorithm

///
// Creating a salt
///

// In PHP, the `hash()` function is used to create a hash.
// Note that some algorithms can be implemented independently, i.e. `sha256()`. Specifications for all of these can be found on the php.net website.

// In this scenario, our aim is to create a secure hash from the user's password.

// As is mentioned in the PHP documentation, the length and variability of the string provided to the `hash()`
// function are the important factors in heightening security.

// Working with large numbers of users, it is likely that some share the same password, username etc. and so creating a hash solely using any
// of these strings would not provide a great deal of security.

// To solve this problem, we create what is known as a 'salt'.
// The salt is a string which is unique to the user and/or application, but which does not contain any sensitive information such as a password or username.
// In addition to being unique, the salt should also be of length equal to or greater than the output. For this example we will create an sha256 hash,
// so the salt should be at least 256 bits long.

// We can create a pseudo-random string that is 256 characters long, however there is no way to ensure that this string will be unique.

// In order to solve this problem, we can utilise the first example in the following article:
// https://www.w3docs.com/snippets/php/how-to-generate-a-random-string-with-php.html

function getRandomString($n) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
  
    for ($i = 0; $i < $n; $i++) {
        $index = rand(0, strlen($characters) - 1);
        $randomString .= $characters[$index];
    }
  
    return $randomString;
}

// To finally create our salt, we use PHP's built-in `time()` function to grab the current UNIX timestamp and then append a random, 256-bit string to it.

$salt = $timestamp . getRandomString(256);


///
// Generating a hash
///

// Once we have our salt, we attach it as a prefix to the user's password and pass it as a parameter to the `hash()` function.
// The first argument of the `hash()` function is a string which defines the algorithm used in hashing. The second argument is the data to be hashed.

$saltPasswordCombination = hash('sha256', $salt . 'Password123');


///
// Additional notes
///

// It is important to remember that this code should only ever be executed client-side, and the user's password should never be transmitted over the internet.

// In a production environment, the salt would only be generated when a user creates a new account.
// The salt would then be stored in a database alongside their username and the value of the `$saltPasswordCombination` variable above,
// but the database would not store the user's password.

// Whenever an existing user attempts to login to the site, the client makes a request to the server and retrieves the salt from the database.
// The client executes the `hash()` function, using the salt from the database in place of the `$salt` variable in the above example.
// The resulting hash is then sent back to the server where it is compared against the hash that was stored in the database when the user created their account.
// If both hashes are the same, then the user must have provided the correct password and is allowed access to the site.
// If the hashes are not the same, then the user must have provided an incorrect password and is not granted access to the site.

// If a user wishes to change their password, a new value is generated using the same salt and the new password and the resulting hash replaces the
// hash that was previously stored in the databas, to be compared against future login attempts.
