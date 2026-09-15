## ADDED Requirements

### Requirement: Reusable authenticated encryption contexts
The cryptographic API SHALL allow a validated key to protect multiple caller-owned messages with explicit nonces without rebuilding its expanded context. AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 MUST preserve existing ciphertext/tag vectors and constant-time authentication. Cached key and authentication state SHALL be destroyed on drop or explicit clearing, and failed authentication SHALL clear the caller's plaintext-capable output.

#### Scenario: Reused context matches independent vectors
- **WHEN** one context seals and opens multiple distinct nonces and message lengths for each supported algorithm
- **THEN** output matches the stateless reference, tampered tags/AAD fail without plaintext, and reuse does not alter previous ciphertext

#### Scenario: Explicitly cleared context is terminal
- **WHEN** a caller clears a reusable context and attempts another operation
- **THEN** no operation succeeds and formatting never reveals key material

### Requirement: Portable accelerated cryptography
Distributed ARM64 builds SHALL enable runtime-detected hardware AES and polynomial multiplication where supported, retain a portable fallback, and produce the same authenticated bytes as other supported architectures.

#### Scenario: Accelerated and portable record agreement
- **WHEN** the same known-answer and in-place tests run with accelerated and forced-portable backends
- **THEN** both pass with identical ciphertext/tag results and valid authentication failures
