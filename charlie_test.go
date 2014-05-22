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
	params, err := New([]byte{
		0x05, 0xd8, 0x4b, 0x3c, 0x5f, 0xf0, 0xd0, 0x86, // 128-bit AES key
		0x6a, 0x08, 0x6e, 0xa9, 0x0b, 0x4a, 0xd4, 0x02,
	})
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/secure", func(w http.ResponseWriter, r *http.Request) {
		// establish that the request is authenticated and resolve a principal
		user := authenticate(r)

		// validate the token, if any
		token := r.Header.Get("CSRF-Token")
		if err := params.Validate(user, token); err != nil {
			http.Error(w, "Invalid CSRF token", http.StatusBadRequest)
			return
		}

		// generate a new token for the response
		token, err := params.Generate(user)
		if err != nil {
			panic(err)
		}
		w.Header().Add("CSRF-Token", token)

		// handle actual request
		// ...
	})
}

func authenticate(r *http.Request) string {
	return ""
}

func TestRoundTrip(t *testing.T) {
	token, err := params.Generate("woo")
	if err != nil {
		t.Fatal(err)
	}

	if err := params.Validate("woo", token); err != nil {
		t.Fatal(err)
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
				token, err := params.Generate("woo")
				if err != nil {
					t.Fatal(err)
				}
				tokens <- token
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
	token, err := params.Generate("woo")
	if err != nil {
		t.Fatal(err)
	}

	timer = func() time.Time {
		return time.Now().Add(20 * time.Minute)
	}
	defer func() {
		timer = time.Now
	}()

	if err := params.Validate("woo", token); err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken but got %v", err)
	}
}

func TestRoundTripBadEncoding(t *testing.T) {
	token, err := params.Generate("woo")
	if err != nil {
		t.Fatal(err)
	}

	if err := params.Validate("woo", "A"+token); err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken but got %v", err)
	}
}

func TestRoundTripBadToken(t *testing.T) {
	token, err := params.Generate("woo")
	if err != nil {
		t.Fatal(err)
	}

	b, _ := base64.URLEncoding.DecodeString(token)
	b[0] ^= 12
	token = base64.URLEncoding.EncodeToString(b)

	if err := params.Validate("woo", token); err != ErrInvalidToken {
		t.Fatalf("Expected ErrInvalidToken but got %v", err)
	}
}

func BenchmarkGenerate(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := params.Generate("yay")
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkValidate(b *testing.B) {
	b.ReportAllocs()
	token, err := params.Generate("yay")
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if params.Validate("yay", token) != nil {
			b.Fatal(err)
		}
	}
}

var params *TokenParams

func init() {
	p, err := New([]byte("ayellowsubmarine"))
	if err != nil {
		panic(err)
	}
	params = p
}
