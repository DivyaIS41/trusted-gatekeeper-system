# IoT Device Module

## Role
The IoT Device acts as the data source in the system.

## Stage C Behavior
For Stage C, the IoT Device creates sensor data with a unique device ID,
timestamp, and nonce. It encrypts the message with the IoT-to-Fog Fernet key and
sends the encrypted token to the Fog Gateway.

## Responsibilities
- Generate data (sensor readings or messages)
- Prepare data for transmission
- Send data only to the Fog Gateway

## What this module does NOT do
- It does not make security decisions
- It does not communicate directly with the Cloud
- It does not detect attacks

## Workflow
1. Generate data
2. Add device ID, timestamp, and nonce
3. Package the data
4. Encrypt the data
5. Send the encrypted data to the Fog Gateway

## Design Principle
The IoT device is intentionally kept simple to reflect real-world resource-constrained devices.
