# Cryptography Module

## Role
This module contains shared cryptographic utilities used by IoT, Fog, and Cloud components.

## Responsibilities
- Encryption and decryption functions
- Key handling logic
- Shared security primitives

## Stage B Implementation
Stage B uses Fernet from the `cryptography` library.

- `fernet_crypto.py` stores fixed demo keys.
- `encrypt_message()` converts a Python dictionary into encrypted text.
- `decrypt_message()` converts encrypted text back into a Python dictionary.

The project uses two keys:

- `IOT_TO_FOG_KEY`: used by IoT to encrypt and Fog to decrypt.
- `FOG_TO_CLOUD_KEY`: used by Fog to encrypt and Cloud to decrypt.

The keys are fixed so the components can restart and still understand each
other. In a real deployment, these keys should be stored in a secret manager or
environment variables instead of source code.

## Design Rule
No component should implement cryptography on its own.
All cryptographic operations must go through this module.
