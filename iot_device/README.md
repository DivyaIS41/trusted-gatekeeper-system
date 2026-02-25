# IoT Device Module

## Role
The IoT Device acts as the data source in the system.

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
2. Package the data
3. Send the data to the Fog Gateway

## Design Principle
The IoT device is intentionally kept simple to reflect real-world resource-constrained devices.