package jwks

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test helper functions
// ============================================================================

type jwksVector struct {
	Description string          `json:"description"`
	JWKS        json.RawMessage `json:"jwks"`
	Valid       bool            `json:"valid"`
	Kids        []string        `json:"kids"`
}

func loadJWKSVectors(tb testing.TB) map[string]jwksVector {
	tb.Helper()

	fsys := os.DirFS(filepath.Join("..", "testdata", "vectors", "jwks"))

	names, err := fs.Glob(fsys, "*.json")
	require.NoError(tb, err)
	require.NotEmpty(tb, names)

	vectors := map[string]jwksVector{}
	for _, name := range names {
		body, err := fs.ReadFile(fsys, name)
		require.NoError(tb, err)

		var v jwksVector
		require.NoError(tb, json.Unmarshal(body, &v))

		vectors[name] = v
	}

	return vectors
}

// ============================================================================
// Tests
// ============================================================================

func TestParseSet_Vectors(t *testing.T) {
	t.Parallel()

	for name, v := range loadJWKSVectors(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			keys, err := ParseSet(v.JWKS)
			if !v.Valid {
				require.Error(t, err, v.Description)

				return
			}

			require.NoError(t, err, v.Description)

			kids := make([]string, 0, len(keys))
			for _, key := range keys {
				kids = append(kids, key.ID)
			}

			assert.Equal(t, v.Kids, kids, v.Description)
		})
	}
}
