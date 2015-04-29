package charlie

import (
	"encoding/base64"
	"net/http"
	"sync"
	"testing"
	"time"
)

func Example() {
	// create a new TokenParams
	params := New([]byte("yay for dumbledore"))

	http.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.Header.Get("Session-ID")

		// validate the token, if any
		token := r.Header.Get("CSRF-Token")
		if err := params.Validate(sessionID, token); err != nil {
			http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
			return
		}

		// generate a new token for the response
		w.Header().Add("CSRF-Token", params.Generate(sessionID))

		// handle actual request
		// ...
	})
}

var params = New([]byte("ayellowsubmarine"))

func TestRoundTrip(t *testing.T) {
	token := params.Generate("woo")

	if err := params.Validate("woo", token); err != nil {
		t.Fatal(err)
	}
}

func TestTokenLength(t *testing.T) {
	token := params.Generate("woo")

	if v, want := len(token), 28; v != want {
		t.Errorf("Token length was %d, but expected %d", v, want)
	}
}

func TestEmptyToken(t *testing.T) {
	if err := params.Validate("woo", ""); err != ErrInvalidToken {
		t.Errorf("Error was %v, but expected ErrInvalidToken", err)
	}
}

func TestRoundTripConcurrent(t *testing.T) {
	tokens := make(chan string, 100)

	producers := 10
	wgP := new(sync.WaitGroup)
	wgP.Add(producers)

	consumers := 10
	wgC := new(sync.WaitGroup)
	wgC.Add(consumers)

	for i := 0; i < producers; i++ {
		go func() {
			defer wgP.Done()
			for j := 0; j < 1000; j++ {
				tokens <- params.Generate("woo")
			}
		}()
	}

	for i := 0; i < consumers; i++ {
		go func() {
			defer wgC.Done()
			for token := range tokens {
				if err := params.Validate("woo", token); err != nil {
					t.Fatal(err)
				}
			}
		}()
	}

	wgP.Wait()
	close(tokens)
	wgC.Wait()
}

func TestRoundTripExpired(t *testing.T) {
	token := params.Generate("woo")

	params.timer = func() time.Time {
		return time.Now().Add(20 * time.Minute)
	}
	defer func() {
		params.timer = time.Now
	}()

	if err := params.Validate("woo", token); err != ErrInvalidToken {
		t.Fatalf("Error was %v, but expected ErrInvalidToken", err)
	}
}

func TestRoundTripBadEncoding(t *testing.T) {
	token := params.Generate("woo")

	if err := params.Validate("woo", "A"+token); err != ErrInvalidToken {
		t.Fatalf("Error was %v, but expected ErrInvalidToken", err)
	}
}

func TestRoundTripBadToken(t *testing.T) {
	token := params.Generate("woo")

	b, _ := base64.URLEncoding.DecodeString(token)
	b[0] ^= 12
	token = base64.URLEncoding.EncodeToString(b)

	if err := params.Validate("woo", token); err != ErrInvalidToken {
		t.Fatalf("Error was %v, but expected ErrInvalidToken", err)
	}
}

func BenchmarkGenerate(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			params.Generate("yay")
		}
	})
}
func BenchmarkValidate(b *testing.B) {
	token := params.Generate("yay")
	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := params.Validate("yay", token); err != nil {
				b.Fatal(err)
			}
		}
	})
}
