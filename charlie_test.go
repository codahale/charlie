package charlie

import (
	"encoding/base64"
	"sync"
	"testing"
	"time"
)

var params *TokenParams

func init() {
	params, _ = New([]byte("ayellowsubmarine"))
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
