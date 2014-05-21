package charlie

import (
	"encoding/base64"
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
	for i := 0; i < b.N; i++ {
		_, err := params.Generate("yay")
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkValidate(b *testing.B) {
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
