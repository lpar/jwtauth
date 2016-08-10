
# jwtauth

This library implements (mostly) stateless web session authentication using
JSON Web Tokens (JWT).

Initiating login and checking credentials is left to the caller, as it depends
heavily on the sign-in technology used. Once you've established who the user is
once, this library gives you a way to track that information securely
throughout your application without needing to keep extensive server-side
state.

Things to note:

 * The tokens are signed and encrypted to prevent tampering, using RSA. Tokens 
   which fail decryption and signature checking are not accepted.

 * Nonce values are embedded in the encrypted tokens as jti parameters, to 
   ensure that tokens cannot be reused and guard against replay attacks.

 * Cookies and tokens are both given expiry periods, to implement idle
   session timeout.

 * Cookies are marked HttpOnly to guard against XSS attacks.

 * Don't forget to protect your forms against CSRF, including your login form.

A handler is provided to deal with protecting routes which require
authentication. The detected identity is passed to the next handler in the
chain using Go's Context mechanism.

Since tokens are one time only, sessions must be kept alive by reissuing
updated tokens. A heartbeat handler is provided to do this for page loads
which do not require authentication.
