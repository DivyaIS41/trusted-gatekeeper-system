# Cloud Server Module

## Role
The Cloud Server is the trusted backend of the system.

## Responsibilities
- Receive verified data from Fog Gateway
- Store data securely
- Maintain logs and audit trails
- Generate reports

## What this module does NOT do
- It does not directly accept data from IoT devices
- It does not perform real-time security enforcement

## Workflow
1. Receive data from Fog Gateway
2. Verify integrity
3. Store data
4. Log events

## Design Principle
The Cloud trusts only the Fog Gateway, not individual devices.