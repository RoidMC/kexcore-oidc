// Package pairwise implements Pairwise Subject Identifiers (OIDC Core §8.1).
//
// When enabled, different clients receive different `sub` values for the
// same user, preventing cross-client user correlation.
//
// The transformation is: sub = BASE64URL(HMAC-SHA256(salt, client_id || subject))
// where salt is derived from the sector_identifier_uri or a server-wide secret.
package pairwise

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

// Transform converts a real subject into a pairwise subject for a given client.
// The same (clientID, subject) pair always produces the same pairwise subject.
func (t *SubjectTransformer) Transform(clientID, subject string) string {
	mac := hmac.New(sha256.New, t.salt)
	mac.Write([]byte(clientID))
	mac.Write([]byte(subject))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
