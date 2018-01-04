package jwtauth

import (
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	pseudorand "math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat/go-jwx/jwa"
	"github.com/lestrrat/go-jwx/jwe"
	"github.com/lestrrat/go-jwx/jwt"
)

var auth *Authenticator

func TestMain(m *testing.M) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Printf("error generating test RSA key: %s", err)
		os.Exit(1)
	}
	auth = NewAuthenticator(privateKey)

	flag.Parse()
	os.Exit(m.Run())
}

var testData = map[string]string{
	"sub":         "test@example.com",
	"name":        "Kevin Mitnick",
	"given_name":  "Kevin",
	"family_name": "Mitnick",
	"email":       "mitnick@example.com",
}

func (auth *Authenticator) testCookieHandler(w http.ResponseWriter, r *http.Request) {
	cs := jwt.NewClaimSet()
	for k, v := range testData {
		err := cs.Set(k, v)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error setting %s value: %s", k, err.Error()), http.StatusInternalServerError)
		}
	}
	err := auth.EncodeToken(w, cs)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// A handler which simply records that it was called and the context it
// was called with
type RecordingHandler struct {
	Called   bool
	ClaimSet *jwt.ClaimSet
}

var recordingHandler = RecordingHandler{}

func (h RecordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Not h, we need to store the values in the global
	recordingHandler.ClaimSet,
		recordingHandler.Called = auth.ClaimSetFromRequest(r)
}

// HandlerFunc method so we can test that wrapper interface too
func (h RecordingHandler) Handle(w http.ResponseWriter, r *http.Request) {
	recordingHandler.ClaimSet,
		recordingHandler.Called = auth.ClaimSetFromRequest(r)
}

func getCookie(r *http.Response, name string) (*http.Cookie, error) {
	cookies := r.Cookies()
	for _, c := range cookies {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("No cookie %s found", name)
}

func getTestCookie(t *testing.T) (*http.Cookie, error) {
	ts := httptest.NewServer(http.HandlerFunc(auth.testCookieHandler))
	defer ts.Close()
	// Subpath to test that cookie path correctly ends up /
	resp, err := http.Get(ts.URL + "/sub/path")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected http response %d", resp.StatusCode)
	}
	ctok, err := getCookie(resp, defaultCookieName)
	if err != nil {
		t.Errorf("Unable to issue token: %s", err)
	}
	return ctok, err
}

func verifyTestCookie(t *testing.T, ctok *http.Cookie) {
	if ctok.Path != "/" {
		t.Errorf("Wrong cookie path, expected / got %s", ctok.Path)
	}
	exp := ctok.Expires
	expexp := time.Now().Add(defaultCookieLifespan)
	durd := expexp.Sub(exp)
	if durd > time.Second {
		t.Errorf("Cookie lifetime incorrect, expected %v got %v", expexp.UTC(), exp.UTC())
	}
	if !ctok.HttpOnly {
		t.Error("Cookie not marked as HttpOnly (XSS vulnerability)")
	}
}

func verifyClaimSet(t *testing.T, cs *jwt.ClaimSet) {
	for k, v := range testData {
		xv := cs.Get(k)
		if xv != v {
			t.Errorf("Wrong %s, expected %s got %s", k, xv, v)
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	// Test encode/issue
	ctok, err := getTestCookie(t)
	if err != nil {
		t.Errorf("Failed to get test cookie: %s", err)
	}
	verifyTestCookie(t, ctok)

	// Test decode
	req, err := http.NewRequest("GET", "/random", nil)
	if err != nil {
		t.Errorf("Unable to create http request: %s", err)
	}
	req.AddCookie(ctok)
	ncs, err := auth.decodeToken(req)
	if err != nil {
		t.Errorf("Token decode failed: %s", err)
	}
	verifyClaimSet(t, ncs)
}

func getWithCookie(ts *httptest.Server, c *http.Cookie) (*http.Response, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(c)
	resp, err := client.Do(req)
	return resp, err
}

func TestHeartbeat(t *testing.T) {
	ctok, err := getTestCookie(t)
	if err != nil {
		t.Errorf("Error getting a test cookie: %s", err)
	}

	ts := httptest.NewServer(auth.TokenHeartbeat(recordingHandler))
	defer ts.Close()

	resp, err := getWithCookie(ts, ctok)
	if err != nil {
		t.Errorf("Error performing heartbeat GET: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected http response %d", resp.StatusCode)
	}
	newtok, err := getCookie(resp, defaultCookieName)
	if err != nil {
		t.Errorf("Bad cookie get on heartbeat: %s", err)
	}
	verifyTestCookie(t, newtok)

	if !recordingHandler.Called {
		t.Errorf("Heartbeat handler didn't pass through to next handler")
	}
	cs := recordingHandler.ClaimSet

	attrs := []string{"sub", "name", "given_name", "family_name", "email"}

	for _, k := range attrs {
		v := cs.Get(k).(string)
		if v != testData[k] {
			t.Errorf("Bad value %s in passthrough context, expected %s got %s", k, testData[k], v)
		}
	}

}

func TestHeartbeatFunc(t *testing.T) {
	ctok, err := getTestCookie(t)
	if err != nil {
		t.Errorf("Error getting a test cookie: %s", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(auth.TokenHeartbeatFunc(recordingHandler.Handle)))
	defer ts.Close()

	resp, err := getWithCookie(ts, ctok)
	if err != nil {
		t.Errorf("Error performing heartbeat GET: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Unexpected http response %d", resp.StatusCode)
	}
	newtok, err := getCookie(resp, defaultCookieName)
	if err != nil {
		t.Errorf("Bad cookie get on heartbeat: %s", err)
	}
	verifyTestCookie(t, newtok)

	if !recordingHandler.Called {
		t.Errorf("Heartbeat handler didn't pass through to next handler")
	}
	cs := recordingHandler.ClaimSet

	attrs := []string{"sub", "name", "given_name", "family_name", "email"}

	for _, k := range attrs {
		v := cs.Get(k).(string)
		if v != testData[k] {
			t.Errorf("Bad value %s in passthrough context, expected %s got %s", k, testData[k], v)
		}
	}

}

func TestLogout(t *testing.T) {
	ctok, err := getTestCookie(t)
	if err != nil {
		t.Errorf("Error getting a test cookie: %s", err)
	}
	ts := httptest.NewServer(auth.Logout(recordingHandler))
	defer ts.Close()

	resp, err := getWithCookie(ts, ctok)
	cook, err := getCookie(resp, defaultCookieName)
	if err != nil {
		t.Errorf("Bad cookie get on logout: %s", err)
	}
	if cook.Name != defaultCookieName {
		t.Error("Cookie not set on logout")
	}
	if cook.Value != "" {
		t.Error("Cookie survived logout")
	}
	if cook.MaxAge > 0 {
		t.Error("Cookie not set to expire on logout")
	}
}

func TestAuthRedirect(t *testing.T) {
	ts := httptest.NewServer(auth.TokenAuthenticate(recordingHandler))
	defer ts.Close()

	resp, err := getWithCookie(ts, &http.Cookie{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Authentication fail (no cookie) didn't redirect, expected %d, got %d",
			http.StatusSeeOther, resp.StatusCode)
	}
}

func TestAuthRedirectFunc(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(auth.TokenAuthenticateFunc(recordingHandler.Handle)))
	defer ts.Close()

	resp, err := getWithCookie(ts, &http.Cookie{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Authentication fail (no cookie) didn't redirect, expected %d, got %d",
			http.StatusSeeOther, resp.StatusCode)
	}
}

func corrupt(x string) string {
	b := []byte(x)
	i := pseudorand.Intn(len(b))
	b[i] = b[i] ^ 1
	return string(b)
}

func TestCorruptCookie(t *testing.T) {
	ts := httptest.NewServer(auth.TokenAuthenticate(recordingHandler))
	defer ts.Close()

	cook, err := getTestCookie(t)
	if err != nil {
		t.Errorf("Error getting a test cookie: %s", err)
	}

	chunks := strings.SplitN(cook.Value, ".", 3)
	if len(chunks) != 3 {
		t.Errorf("JWT had wrong number of chunks, expected 3 got %d", len(chunks))
	}
	// Chunks are header, payload and signature. Let's try corrupting the
	// signature.
	badsig := fmt.Sprintf("%s.%s.%s", chunks[0], chunks[1], corrupt(chunks[2]))
	cook.Value = badsig

	resp, err := getWithCookie(ts, &http.Cookie{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("Authentication fail (bad cookie) didn't redirect, expected %d, got %d",
			http.StatusSeeOther, resp.StatusCode)
	}
}

// Make sure we don't succeed or cause a panic trying to fetch a ClaimSet
// from a request which lacks one
func TestSafeCSGet(t *testing.T) {
	r := &http.Request{}
	_, ok := auth.ClaimSetFromRequest(r)
	if ok {
		t.Errorf("ClaimSetFromRequest returned OK from Request with no ClaimSet")
	}
}

// Make sure that a cookie with the user's choice of a1gorithm won't work,
// even if they had the right keys.
//
// The theory is that anyone can can get the public key, and if a token is signed with HS256 and the public key,
// it will successfully verify when decoded using the private key, because HMAC-SHA is symmetric.
//
// See <https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/>
func TestEvilAlgo(t *testing.T) {

	// Construct a claimset complete with valid iat, jti
	cs := jwt.NewClaimSet()
	for k, v := range testData {
		err := cs.Set(k, v)
		if err != nil {
			t.Errorf("Error setting %s value: %s", k, err)
		}
	}
	err := cs.Set("iat", time.Now().Unix())
	if err != nil {
		t.Errorf("can't set iat value: %s", err)
	}
	jti := int64(auth.SerialGen.Generate())
	err = cs.Set("jti", strconv.FormatInt(jti, jtiNumericBase))
	if err != nil {
		t.Errorf("can't set jti value: %s", err)
	}
	badtok, err := cs.MarshalJSON()
	if err != nil {
		t.Errorf("token marshalling error: %s", err)
	}

	enc, err := jwe.Encrypt(badtok, jwa.RSA1_5, &auth.PrivateKey.PublicKey, jwa.A128CBC_HS256, jwa.Deflate)
	if err != nil {
		t.Errorf("token encryption error: %s", err)
	}

	expires := time.Now().Add(time.Hour)

	cookie := &http.Cookie{
		Name:     auth.CookieName,
		Value:    string(enc),
		Expires:  expires,
		MaxAge:   86400,
		HttpOnly: true,
		Path:     "/",
	}

	req, err := http.NewRequest("GET", "/random", nil)
	if err != nil {
		t.Errorf("Unable to create http request: %s", err)
	}
	req.AddCookie(cookie)

	_, err = auth.decodeToken(req)
	if err == nil {
		t.Errorf("Malicious signed token decode succeeded!")
	}

}

// Make sure that an unencrypted JWT assembled with algorithm 'none' is not accepted.
func TestEvil(t *testing.T) {

	eviltoken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibmFtZSI6IktldmluIE1pdG5pY2siLCJnaXZlbl9uYW1lIjoiS2V2aW4iLCJmYW1pbHlfbmFtZSI6Ik1pdG5pY2siLCJlbWFpbCI6Im1pdG5pY2tAZXhhbXBsZS5jb20ifQ.NzG-9jkRvm7UFkgiGdpBUottduDbSXY9xMq_EqrXdO4"

	expires := time.Now().Add(time.Hour)

	cookie := &http.Cookie{
		Name:     auth.CookieName,
		Value:    eviltoken,
		Expires:  expires,
		MaxAge:   86400,
		HttpOnly: true,
		Path:     "/",
	}

	req, err := http.NewRequest("GET", "/random", nil)
	if err != nil {
		t.Errorf("Unable to create http request: %s", err)
	}
	req.AddCookie(cookie)

	_, err = auth.decodeToken(req)
	if err == nil {
		t.Errorf("Malicious token decode succeeded!")
	}
}
