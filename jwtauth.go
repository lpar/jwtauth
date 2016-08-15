// jwtauth implements (mostly) stateless web session authentication using JSON
// Web Tokens (JWT).
package jwtauth

import (
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwe"
	"github.com/lestrrat/go-jwx/jwt"
	"github.com/lpar/serial"
	"github.com/rs/xhandler"
	"golang.org/x/net/context"
)

// Authenticator provides a structure for the run-time parameters controlling
// authentication.
type Authenticator struct {
	CookieName     string        // Name to use for cookie
	CookieLifespan time.Duration // How long tokens and cookies should live for
	ContextName    string        // Name to use
	LoginURL       string        // URL to initiate re-login on session fail
	PrivateKey     *rsa.PrivateKey
	SerialGen      *serial.Generator
	GC             chan struct{} // Channel to control JTI nonce GC
}

const defaultCookieName = "token"
const defaultCookieLifespan = time.Hour / 3
const defaultContextName = "context"
const defaultLoginURL = "/login"

// NewAuthenticator sets up a new Authenticator object with sensible defaults,
// using the provided RSA private key.

// Once any parameters have been updated to taste, you can call StartGC to
// begin a periodic background task which will expire old data from the jti
// nonce blacklist. If you don't do so, you should call ExpireSeen yourself
// periodically to make sure memory doesn't fill up.
func NewAuthenticator(rsakey *rsa.PrivateKey) *Authenticator {
	auth := &Authenticator{
		CookieName:     defaultCookieName,
		CookieLifespan: defaultCookieLifespan,
		ContextName:    defaultContextName,
		LoginURL:       defaultLoginURL,
		SerialGen:      serial.NewGenerator(),
		PrivateKey:     rsakey,
	}
	return auth
}

// StartGC starts a periodic garbage collector which runs in a separate
// goroutine, and cleans out old data from the jti (nonce) blacklist.
// You should call it once, after any changes to the CookieLifespan parameter.
// GC runs are performed at an interval of (cookie lifespan / 2).
func (auth *Authenticator) StartGC() {
	auth.GC = auth.NewGarbageCollector()
}

// StopGC stops the garbage collector task, in case you want to stop it but
// leave the application active.
func (auth *Authenticator) StopGC() {
	close(auth.GC)
}

// Used when generating JTI values from int64 values, to make them as compact
// as possible
const jtiNumericBase = 36

// Logout triggers a logout by refreshing the cookie with an empty value and
// an expiry time indicating that it should immediately be deleted.
func (auth *Authenticator) Logout(next ...xhandler.HandlerC) xhandler.HandlerC {
	return xhandler.HandlerFuncC(func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		cookie := &http.Cookie{
			Name:     auth.CookieName,
			Value:    "",
			MaxAge:   -1,
			HttpOnly: true,
			Path:     "/",
		}
		http.SetCookie(w, cookie)
		if len(next) == 0 {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		next[0].ServeHTTPC(ctx, w, r)
	})
}

// decodeToken extracts the JWT authentication token from the cookies of the
// supplied http Request. The token is decrypted and its expiry time checked.
// If the token is cryptographically secure and unexpired, it is returned.
// Otherwise an error value is returned.
func (auth *Authenticator) decodeToken(r *http.Request) (*jwt.ClaimSet, error) {

	cs := jwt.NewClaimSet()

	// Get token cookie
	ctok, err := r.Cookie(auth.CookieName)
	if err != nil {
		return cs, fmt.Errorf("no token cookie '%s'", auth.CookieName)
	}

	// Decode it
	stok := ctok.Value
	dec, err := jwe.Decrypt([]byte(stok), jwa.RSA1_5, auth.PrivateKey)
	if err != nil {
		return cs, err
	}

	err = cs.UnmarshalJSON(dec)
	if err != nil {
		return cs, err
	}

	// Check we got something worthwhile
	sub := cs.Get("sub").(string)
	if sub == "" {
		log.Printf("[DEBUG] claimset for no subject")
		return cs, fmt.Errorf("empty claimset (no subject)")
	}
	log.Printf("[DEBUG] claimset for %s", sub)

	// Check it hasn't expired
	tokex := cs.Get("exp").(int64)
	if tokex < time.Now().Unix() {
		return cs, fmt.Errorf("token for %s expired at %s", cs.Get("sub"),
			time.Unix(tokex, 0))
	}

	// Check it hasn't already been used
	jti := cs.Get("jti").(string)
	if jti == "" {
		return cs, fmt.Errorf("token with no jti")
	}
	jtiint, err := strconv.ParseInt(jti, jtiNumericBase, 64)
	if err != nil {
		return cs, fmt.Errorf("garbage jti in token: %s", jti)
	}
	if auth.SerialGen.Seen(serial.Serial(jtiint)) {
		return cs, fmt.Errorf("attempt to reuse token: %s", jti)
	}
	auth.SerialGen.SetSeen(serial.Serial(jtiint))

	// Success!
	return cs, nil
}

// NewGarbageCollector starts a goroutine to perform periodic garbage
// collection of the jti nonce blacklist. Usually you'll just call StartGC
// instead.
func (auth *Authenticator) NewGarbageCollector() chan struct{} {
	ticker := time.NewTicker(auth.CookieLifespan / 2)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				auth.SerialGen.ExpireSeen(auth.CookieLifespan)
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
	return quit
}

// EncodeToken encodes a jwt.ClaimSet into a cookie and sends it to the
// browser client.
func (auth *Authenticator) EncodeToken(w http.ResponseWriter, cs *jwt.ClaimSet) error {

	expires := time.Now().Add(auth.CookieLifespan)
	log.Printf("[DEBUG] encode token exp = %s unix = %d", expires, expires.Unix())
	cs.Set("exp", expires.Unix())
	cs.Set("iat", time.Now().Unix())
	jti := int64(auth.SerialGen.Generate())
	cs.Set("jti", strconv.FormatInt(jti, jtiNumericBase))
	ntok, err := cs.MarshalJSON()
	if err != nil {
		return fmt.Errorf("token marshalling error: %s", err)
	}

	enc, err := jwe.Encrypt(ntok, jwa.RSA1_5, &auth.PrivateKey.PublicKey, jwa.A128CBC_HS256, jwa.Deflate)
	if err != nil {
		return fmt.Errorf("token encryption error: %s", err)
	}

	cookie := &http.Cookie{
		Name:     auth.CookieName,
		Value:    string(enc),
		Expires:  expires,
		MaxAge:   int(auth.CookieLifespan.Seconds()),
		HttpOnly: true,
		Path:     "/",
	}

	// Send it back to the browser
	http.SetCookie(w, cookie)

	return nil
}

// tokenReissueHandler deals with the details of authentication token
// checking and reissuing. If enforce is true, lack of a valid token
// results in a redirection to the login page and the next handler NOT
// being called; otherwise the token is allowed to expire silently.
func (auth *Authenticator) tokenReissueHandler(xhnd xhandler.HandlerC, enforce bool) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		ctx := context.Background()

		if auth.PrivateKey == nil {
			panic("No private key!")
		}

		tok, err := auth.decodeToken(r)
		if err != nil {
			log.Printf("[WARN] Invalid token: %s", err)
			if enforce {
				// Status 303 = change to GET when redirecting
				http.Redirect(w, r, auth.LoginURL, http.StatusSeeOther)
				return
			}
		} else {
			// Token heartbeat -- it was valid so issue an updated one
			auth.EncodeToken(w, tok)

			// Put the claimset in the context for the next handler
			ctx = context.WithValue(ctx, auth.ContextName, tok)
		}

		// Call the next handler in the chain
		xhnd.ServeHTTPC(ctx, w, r)
	})
}

// TokenAuthenticate wraps a HandlerC and requires a valid token (i.e.
// requires authentication), or else the user is redirected to the login
// page and the next handler is NOT called.
func (auth *Authenticator) TokenAuthenticate(xhnd xhandler.HandlerC) http.Handler {
	return auth.tokenReissueHandler(xhnd, true)
}

// TokenHeartbeat wraps a HandlerC and performs heartbeat update of any
// token found, but does not require a token (i.e does not require
// authentication).
func (auth *Authenticator) TokenHeartbeat(xhnd xhandler.HandlerC) http.Handler {
	return auth.tokenReissueHandler(xhnd, false)
}
