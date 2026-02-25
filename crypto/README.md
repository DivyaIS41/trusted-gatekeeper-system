# Cryptography Module

## Role
This module contains shared cryptographic utilities used by IoT, Fog, and Cloud components.

## Responsibilities
- Encryption and decryption functions
- Key handling logic
- Shared security primitives

## Design Rule
No component should implement cryptography on its own.
All cryptographic operations must go through this module.