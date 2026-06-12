// Package crypto test exports — package-level helpers compiled only during tests.
package crypto

// NewLegacyAESGCMEncryptorForTest creates an AESGCMEncryptor that uses the
// pre-v2 AAD format (project+env only, no key name). Used by tests to produce
// ciphertexts that simulate blobs encrypted before the key-name binding fix,
// verifying the backward-compat fallback in Decrypt.
func NewLegacyAESGCMEncryptorForTest(passphrase, project, env string) (*AESGCMEncryptor, error) {
	enc, err := NewAESGCMEncryptor(passphrase, project, env, "")
	if err != nil {
		return nil, err
	}
	// Override AAD to the legacy format.
	enc.aad = enc.legacyAAD
	return enc, nil
}
