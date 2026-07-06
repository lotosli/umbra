## ADDED Requirements

### Requirement: X25519 Diffie-Hellman
The crate SHALL provide X25519 keypair generation and ECDH agreement conforming to RFC 7748, and the agreement MUST be symmetric between the two parties.

#### Scenario: Shared secret is symmetric
- **WHEN** two parties generate keypairs and each computes ECDH against the peer's public key
- **THEN** both derive the identical 32-byte shared secret

#### Scenario: Known-answer vector
- **WHEN** computing X25519 over an RFC 7748 test vector
- **THEN** the result equals the vector's expected shared secret

### Requirement: HKDF-SHA256 key derivation
The crate SHALL provide HKDF-SHA256 extract-and-expand conforming to RFC 5869.

#### Scenario: RFC 5869 vectors
- **WHEN** deriving output keying material for the RFC 5869 SHA-256 test cases
- **THEN** the OKM equals the expected output for each case

### Requirement: Constant-time HMAC verification
The crate SHALL provide HMAC-SHA256 and MUST verify tags in constant time.

#### Scenario: Reject tampered tag
- **WHEN** verifying a message whose tag differs from the correct tag by one bit
- **THEN** verification returns a negative result and never the plaintext

#### Scenario: Accept valid tag
- **WHEN** verifying a message with its correct tag
- **THEN** verification succeeds

### Requirement: AEAD seal and open
The crate SHALL provide AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 authenticated encryption with associated data.

#### Scenario: Round-trip
- **WHEN** sealing plaintext under a key, nonce and AAD, then opening the ciphertext with the same key, nonce and AAD
- **THEN** the recovered plaintext equals the original

#### Scenario: Reject wrong associated data
- **WHEN** opening a ciphertext with a different AAD than was used to seal it
- **THEN** open returns an error and yields no plaintext

### Requirement: ChaCha20 keystream
The crate SHALL provide the ChaCha20 stream cipher conforming to RFC 8439.

#### Scenario: RFC 8439 vector
- **WHEN** XORing the input against the ChaCha20 keystream for an RFC 8439 test vector
- **THEN** the output matches the expected ciphertext

### Requirement: Secret zeroization
Secret key types SHALL be zeroized on drop and MUST NOT expose their bytes through Debug or Display.

#### Scenario: No debug leak
- **WHEN** formatting a secret type via its Debug implementation
- **THEN** the output does not contain the raw secret bytes
