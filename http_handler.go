package charlie

import (
	"log"
	"net/http"
	"time"
)

// HTTPParams provides configuration for wrapping an http.Handler
// to check the validity of a CSRF token before permitting a request.
type HTTPParams struct {
	InvalidHandler http.Handler

	Key []byte

	CSRFCookie string
	CSRFHeader string

	SessionCookie string
	SessionHeader string
}

// Wrap wraps an http.Handler to check the validity of a CSRF token.
// It only serves requests where a valid ID/token pair can be found in
// either the request headers or cookies. Otherwise, it calls the InvalidHandler
// or returns an empty 403.
func (hp *HTTPParams) Wrap(h http.Handler) http.Handler {
	csrf := New(hp.Key)
	csrf.MaxAge = 3 * time.Hour

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := headerOrCookieValue(r, hp.CSRFHeader, hp.CSRFCookie)
		id := headerOrCookieValue(r, hp.SessionHeader, hp.SessionCookie)

		var valid bool

		if token != "" && id != "" {
			err := csrf.Validate(id, token)
			if err == nil {
				valid = true
			} else if err != ErrInvalidToken {
				// This should never occur
				panic(err)
			}
		}

		if valid {
			h.ServeHTTP(w, r)
		} else if hp.InvalidHandler != nil {
			hp.InvalidHandler.ServeHTTP(w, r)
		} else {
			log.Printf("Rejected request with an invalid CSRF token=%q for session=%q. (event=csrf_invalid)",
				token, id)
			w.WriteHeader(http.StatusForbidden)
		}
	})
}

func headerOrCookieValue(r *http.Request, headerName, cookieName string) string {
	if headerName != "" {
		token := r.Header.Get(headerName)
		if token != "" {
			return token
		}
	}

	if cookieName != "" {
		cookie, err := r.Cookie(cookieName)
		if err == nil {
			return cookie.Value
		} else if err != http.ErrNoCookie {
			// This should never occur
			panic(err)
		}
	}

	return ""
}
