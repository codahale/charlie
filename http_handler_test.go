package charlie

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	testCSRFHeader    = "csrf-hdr"
	testCSRFCookie    = "csrf-ck"
	testSessionHeader = "s-hdr"
	testSessionCookie = "s-ck"
	testKey           = "superdupersecret"
	testSessionID     = "mysession"
)

var noContentHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(204)
})

func TestHTTPWrapping(t *testing.T) {
	v := HTTPParams{
		Key:           []byte(testKey),
		CSRFHeader:    testCSRFHeader,
		CSRFCookie:    testCSRFCookie,
		SessionCookie: testSessionCookie,
		SessionHeader: testSessionHeader,
	}

	csrf := New(v.Key)
	token := csrf.Generate(testSessionID)

	handler := v.Wrap(noContentHandler)

	// Valid pair in cookies
	req := http.Request{Header: http.Header{}}
	req.AddCookie(&http.Cookie{
		Name:    testCSRFCookie,
		Value:   token,
		Expires: time.Now().AddDate(10, 0, 0),
	})
	req.AddCookie(&http.Cookie{
		Name:    testSessionCookie,
		Value:   testSessionID,
		Expires: time.Now().AddDate(10, 0, 0),
	})

	res := httptest.ResponseRecorder{}
	handler.ServeHTTP(&res, &req)
	if res.Code != 204 {
		t.Errorf("Expected to receive a 204 with correct CSRF token, got %d", res.Code)
	}

	// Valid pair in headers
	hdr := http.Header{}
	hdr.Set(testCSRFHeader, token)
	hdr.Set(testSessionHeader, testSessionID)

	res = httptest.ResponseRecorder{}
	handler.ServeHTTP(&res, &http.Request{Header: hdr})
	if res.Code != 204 {
		t.Fatalf("Expected to receive a 204 with correct CSRF token, got %d", res.Code)
	}

	// Incorrect session/token pair
	hdr.Set(testSessionHeader, "notasession")

	res = httptest.ResponseRecorder{}
	handler.ServeHTTP(&res, &http.Request{Header: hdr})
	if res.Code != http.StatusForbidden {
		t.Errorf("Expected to receive a 403 with an incorrect session, got %d", res.Code)
	}

	// Missing session header
	hdr.Del(testSessionHeader)

	res = httptest.ResponseRecorder{}
	handler.ServeHTTP(&res, &http.Request{Header: hdr})
	if res.Code != http.StatusForbidden {
		t.Errorf("Expected to receive a 403 with an incorrect session, got %d", res.Code)
	}

	// Custom InvalidHandler
	v.InvalidHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(444)
	})

	res = httptest.ResponseRecorder{}
	handler.ServeHTTP(&res, &http.Request{Header: hdr})
	if res.Code != 444 {
		t.Errorf("Expected to receive a 444 with a custom handler, got %d", res.Code)
	}
}

func TestHTTPWrappingMisconfiguration(t *testing.T) {
	v := HTTPParams{}

	handler := v.Wrap(noContentHandler)

	res := httptest.ResponseRecorder{}
	handler.ServeHTTP(&res, &http.Request{})
	if res.Code != http.StatusForbidden {
		t.Fatalf("Expected to receive a 403 without configuration, got %d", res.Code)
	}

	v.Key = []byte(testKey)

	res = httptest.ResponseRecorder{}
	handler.ServeHTTP(&res, &http.Request{})
	if res.Code != http.StatusForbidden {
		t.Fatalf("Expected to receive a 403 with missing header/cookie configuration, got %d", res.Code)
	}

}
