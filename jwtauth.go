// Package jwtauth implements (mostly) stateless web session authentication
// using JSON Web Tokens (JWT).
package jwtauth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwe"
	"github.com/lestrrat/go-jwx/jwt"
	"github.com/lpar/serial"
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
const defaultContextName = "jwtauth"
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
func (auth *Authenticator) Logout(next ...http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		next[0].ServeHTTP(w, r)
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
		return cs, fmt.Errorf("empty claimset (no subject)")
	}

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
	err := cs.Set("exp", expires.Unix())
	if err != nil {
		return fmt.Errorf("can't set exp value: %s", err)
	}
	err = cs.Set("iat", time.Now().Unix())
	if err != nil {
		return fmt.Errorf("can't set iat value: %s", err)
	}
	jti := int64(auth.SerialGen.Generate())
	if err != nil {
		return fmt.Errorf("can't set jti value: %s", err)
	}
	err = cs.Set("jti", strconv.FormatInt(jti, jtiNumericBase))
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

// tokenReissue handles the guts of the authentication. It checks for a token,
// and if a valid token is found, a new token is issued. If no valid token is
// found and 'enforce' is set to true, it issues a redirect to the LoginURL.
func (auth *Authenticator) tokenReissue(w http.ResponseWriter, r *http.Request, enforce bool) *http.Request {
	ctx := r.Context()

	if auth.PrivateKey == nil {
		panic("No private key!")
	}

	tok, err := auth.decodeToken(r)
	if err != nil {
		if enforce {
			// Status 303 = change to GET when redirecting
			http.Redirect(w, r, auth.LoginURL, http.StatusSeeOther)
			return r
		}
	} else {
		// Token heartbeat -- it was valid so issue an updated one
		err := auth.EncodeToken(w, tok)
		if err != nil {
			http.Error(w, "Error encoding JSON Web Token", http.StatusInternalServerError)
			return r
		}

		// Put the claimset in the request context for the next handler
		ctx = context.WithValue(ctx, auth.ContextName, tok)
		r = r.WithContext(ctx)
	}
	return r
}

// tokenReissueHandler returns a Handler which calls tokenReissue.
func (auth *Authenticator) tokenReissueHandler(xhnd http.Handler, enforce bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = auth.tokenReissue(w, r, enforce)
		xhnd.ServeHTTP(w, r)
	})
}

// tokenReissueFunc returns a HandlerFunc which calls tokenReissue.
func (auth *Authenticator) tokenReissueFunc(fn http.HandlerFunc, enforce bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r = auth.tokenReissue(w, r, enforce)
		fn(w, r)
	}
}

// TokenAuthenticate wraps a Handler and requires a valid token (i.e.
// requires authentication), or else the user is redirected to the login
// page and the next handler is NOT called.
func (auth *Authenticator) TokenAuthenticate(xhnd http.Handler) http.Handler {
	return auth.tokenReissueHandler(xhnd, true)
}

// TokenHeartbeat wraps a Handler and performs heartbeat update of any
// token found, but does not require a token (i.e does not require
// authentication).
func (auth *Authenticator) TokenHeartbeat(xhnd http.Handler) http.Handler {
	return auth.tokenReissueHandler(xhnd, false)
}

// TokenAuthenticateFunc is a HandlerFunc version of TokenAuthenticate.
// It wraps a HandlerFunc instead of wrapping a Handler.
func (auth *Authenticator) TokenAuthenticateFunc(fn http.HandlerFunc) http.HandlerFunc {
	return auth.tokenReissueFunc(fn, true)
}

// TokenHeartbeatFunc is a HandlerFunc version of TokenHeartbeat.
// It wraps a HandlerFunc instead of wrapping a Handler.
func (auth *Authenticator) TokenHeartbeatFunc(fn http.HandlerFunc) http.HandlerFunc {
	return auth.tokenReissueFunc(fn, false)
}

// ClaimSetFromRequest is a convenience function to fetch the claimset
// from the context on the request object.
func (auth *Authenticator) ClaimSetFromRequest(r *http.Request) (*jwt.ClaimSet, bool) {
	ctx := r.Context()
	if ctx == nil {
		return nil, false
	}
	cs, ok := ctx.Value(auth.ContextName).(*jwt.ClaimSet)
	return cs, ok
}
