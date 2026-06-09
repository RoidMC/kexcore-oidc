package pairwise

import "github.com/roidmc/kexcore-oidc/pkg/storm"

// Compile-time interface check.
var _ storm.PairwiseTransformer = (*SubjectTransformer)(nil)

// SubjectTransformer transforms a real subject into a pairwise subject.
type SubjectTransformer struct {
	salt     []byte
	pairwise map[string]bool // clientID -> uses pairwise
}

// NewSubjectTransformer creates a new pairwise subject transformer.
// The salt should be a stable secret (e.g., derived from sector_identifier_uri
// or a server configuration).
func NewSubjectTransformer(salt []byte) *SubjectTransformer {
	return &SubjectTransformer{
		salt:     salt,
		pairwise: make(map[string]bool),
	}
}

// SetPairwiseClient marks a client as using pairwise subject identifiers.
func (t *SubjectTransformer) SetPairwiseClient(clientID string) {
	t.pairwise[clientID] = true
}

// IsPairwiseClient returns true if the client uses pairwise subject identifiers.
func (t *SubjectTransformer) IsPairwiseClient(clientID string) bool {
	return t.pairwise[clientID]
}
