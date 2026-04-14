# Cloud Server Module

## Role
The Cloud Server is the trusted backend of the system.

## Stage C Behavior
For Stage C, the Cloud Server receives only messages that passed Fog-side
Zero-Trust checks. It decrypts Fog-to-Cloud messages and prints the plaintext
data.

## Logging Behavior
The Cloud Server logs:

- Accepted messages forwarded by Fog
- Blocked-message reports sent by Fog
- Reasons for blocked-message reports

Cloud logs are written to:

```text
logs/cloud_audit.log
```

## Responsibilities
- Receive verified data from Fog Gateway
- Store data securely
- Maintain logs and audit trails
- Generate reports

## What this module does NOT do
- It does not directly accept data from IoT devices
- It does not perform real-time security enforcement

## Workflow
1. Receive encrypted data from Fog Gateway
2. Decrypt the forwarded message
3. Print the plaintext data
4. Log accepted or blocked-message audit event

## Design Principle
The Cloud trusts only the Fog Gateway, not individual devices.
