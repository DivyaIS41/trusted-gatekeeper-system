# Fog Gateway Module

## Role
The Fog Gateway is the core security component of the system.

## Stage C Behavior
For Stage C, the Fog Gateway receives encrypted TCP messages from the IoT
Device, decrypts them with the IoT-to-Fog Fernet key, and applies Zero-Trust
checks before forwarding anything to the Cloud Server.

The Fog rejects:

- Unknown device IDs
- Old timestamps
- Reused nonces
- Too many messages from one device in a short time

## Responsibilities
- Receive data from IoT devices
- Verify device identity and message validity
- Enforce Zero-Trust security rules
- Detect and block malicious behavior
- Forward only verified data to the Cloud Server

## Why Fog is Critical
- Attacks are stopped before reaching the cloud
- Reduces cloud load
- Enables real-time decision-making

## Workflow
1. Receive encrypted data from IoT device
2. Decrypt the IoT message
3. Check the device ID against the trusted device list
4. Check that the timestamp is fresh
5. Check that the nonce has not been used before
6. Check that the device is not flooding the Fog
7. Re-encrypt accepted data
8. Send encrypted data to Cloud

## Attack Logging
Rejected attack traffic is logged to:

```text
logs/fog_security.log
```

The Fog also sends an encrypted blocked-message report to the Cloud. This lets
Cloud log the security decision without receiving blocked traffic as real sensor
data.

## Design Principle
The Fog Gateway acts as a security enforcement point and should never blindly trust incoming data.
