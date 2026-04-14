# Attack Simulation Module

## Role
This module is used to simulate malicious behavior and validate system security.

## Purpose
- Demonstrate fake device attacks
- Demonstrate replay attacks
- Demonstrate flooding and DoS attempts

## How to Run
Start the normal system first.

Terminal 1:
```bash
python -m cloud_server.server
```

Terminal 2:
```bash
python -m fog_gateway.gateway
```

Then run one attack from a third terminal.

Fake device attack:
```bash
python -m attacks.fake_device_attack
```

Replay attack:
```bash
python -m attacks.replay_attack
```

Flooding attack:
```bash
python -m attacks.flooding_attack
```

## Attack 1: Fake Device
A fake device attack uses a device ID that is not in the Fog Gateway trusted
device list.

Expected attacker output:
```text
[Attack: Fake Device] Fog response: {'status': 'rejected', 'receiver': 'fog', 'details': 'Unknown device ID: iot-device-999', 'event_type': 'fake_device_attack'}
```

Expected Fog output:
```text
[Fog] Message rejected: Unknown device ID: iot-device-999
[Fog][Security] ... event=fake_device_attack | reason=Unknown device ID: iot-device-999 | ...
```

## Attack 2: Replay
A replay attack sends the same message again. The first message may pass, but
the second message must be rejected because it reuses the same nonce.

Expected attacker output:
```text
[Attack: Replay] First Fog response: {'status': 'forwarded', ...}
[Attack: Replay] Second Fog response: {'status': 'rejected', 'receiver': 'fog', 'details': 'Nonce was already used.', 'event_type': 'replay_attack'}
```

Expected Fog output:
```text
[Fog] Message accepted: Message passed Zero-Trust checks.
[Fog] Message rejected: Nonce was already used.
[Fog][Security] ... event=replay_attack | reason=Nonce was already used. | ...
```

## Attack 3: Flooding or DoS
A flooding attack sends many messages very quickly. The Fog Gateway tracks recent
messages per device and blocks traffic when a trusted device sends too many
messages inside the rate-limit window.

Expected attacker output:
```text
[Attack: Flooding] Fog response 1: {'status': 'forwarded', ...}
...
[Attack: Flooding] Fog response 6: {'status': 'rejected', 'receiver': 'fog', 'details': 'Flooding detected: too many messages in a short time.', 'event_type': 'flooding_attack'}
```

Expected Fog output:
```text
[Fog] Message rejected: Flooding detected: too many messages in a short time.
[Fog][Security] ... event=flooding_attack | reason=Flooding detected: too many messages in a short time. | ...
```

## Logs
The Fog Gateway writes attack decisions to:

```text
logs/fog_security.log
```

## Important Note
Attack simulations are a core part of the project and are not optional extras.
They provide proof of security.
