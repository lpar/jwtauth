package jwtauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

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
		cs.Set(k, v)
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
	Called  bool
	Context context.Context
}

var recordingHandler = RecordingHandler{}

func (h RecordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Called = true
	h.Context = r.Context()
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
		t.Fatalf("unexpected http response %d", resp.StatusCode)
	}
	ctok, err := getCookie(resp, defaultCookieName)
	if err != nil {
		t.Errorf("unable to issue token: %s", err)
	}
	return ctok, err
}

func verifyTestCookie(t *testing.T, ctok *http.Cookie) {
	if ctok.Path != "/" {
		t.Errorf("wrong cookie path, expected / got %s", ctok.Path)
	}
	exp := ctok.Expires
	expexp := time.Now().Add(defaultCookieLifespan)
	durd := expexp.Sub(exp)
	if durd > time.Second {
		t.Errorf("cookie lifetime incorrect, expected %v got %v", expexp.UTC(), exp.UTC())
	}
	if ctok.HttpOnly != true {
		t.Error("cookie not marked as HttpOnly (XSS vulnerability)")
	}
}

func verifyClaimSet(t *testing.T, cs *jwt.ClaimSet) {
	for k, v := range testData {
		xv := cs.Get(k)
		if xv != v {
			t.Errorf("wrong %s, expected %s got %s", k, xv, v)
		}
	}
}

func TestEncodeDecode(t *testing.T) {
	// Test encode/issue
	ctok, err := getTestCookie(t)
	if err != nil {
		t.Errorf("failed to get test cookie: %s", err)
	}
	verifyTestCookie(t, ctok)

	// Test decode
	req, err := http.NewRequest("GET", "/random", nil)
	if err != nil {
		t.Errorf("unable to create http request: %s", err)
	}
	req.AddCookie(ctok)
	ncs, err := auth.decodeToken(req)
	if err != nil {
		t.Errorf("token decode failed: %s", err)
	}
	verifyClaimSet(t, ncs)
}

func getWithCookie(ts *httptest.Server, c *http.Cookie) (*http.Response, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", ts.URL, nil)
	req.AddCookie(c)
	resp, err := client.Do(req)
	return resp, err
}

func TestHeartbeat(t *testing.T) {
	ctok, err := getTestCookie(t)
	if err != nil {
		t.Errorf("error getting a test cookie: %s", err)
	}

	ts := httptest.NewServer(auth.TokenHeartbeat(recordingHandler))
	defer ts.Close()

	resp, err := getWithCookie(ts, ctok)
	if err != nil {
		t.Errorf("error performing heartbeat GET: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected http response %d", resp.StatusCode)
	}
	newtok, err := getCookie(resp, defaultCookieName)
	verifyTestCookie(t, newtok)
}
