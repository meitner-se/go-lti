package jwks

import "testing"

func FuzzParseSet(f *testing.F) {
	for _, v := range loadJWKSVectors(f) {
		f.Add([]byte(v.JWKS))
	}

	f.Add([]byte(`{"keys":[{"kty":"RSA","n":"","e":"AQAB"}]}`))
	f.Add([]byte(`{"keys":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := ParseSet(data)
		if err != nil {
			return
		}

		if len(keys) == 0 {
			t.Fatal("ParseSet returned no keys and no error")
		}

		for _, key := range keys {
			if key.PublicKey == nil || key.PublicKey.N.BitLen() < MinRSABits || key.PublicKey.E < 3 {
				t.Fatalf("ParseSet returned an unusable key: %+v", key)
			}
		}
	})
}
