## ADDED Requirements

### Requirement: ML-KEM-768 wrapper
The system SHALL provide ML-KEM-768 key generation, encapsulation, and decapsulation wrappers using the workspace dependency catalog.

#### Scenario: Encapsulation shared secret matches decapsulation
- **WHEN** a generated ML-KEM public key encapsulates a secret and the matching private key decapsulates it
- **THEN** both sides produce the same shared secret bytes

### Requirement: ML-DSA-65 wrapper
The system SHALL provide ML-DSA-65 key generation from a 32-byte seed, signing, and verification.

#### Scenario: Valid signature verifies
- **WHEN** a message is signed with the generated ML-DSA private key
- **THEN** verification with the matching public key succeeds

#### Scenario: Tampered signature is rejected
- **WHEN** either the signed message or the signature bytes are modified
- **THEN** verification returns false

### Requirement: PQ secret handling
The system SHALL zeroize private keys, decapsulation keys, shared secrets, and signing seeds on drop where the underlying type permits it.

#### Scenario: PQ secret debug output is redacted
- **WHEN** a PQ secret wrapper is formatted for debugging
- **THEN** the output does not contain the raw secret bytes
