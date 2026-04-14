# Reports Module

## Role
The Reports module reads Fog and Cloud log files and prints a small security
summary.

## What It Counts
- Fog security events such as fake device, replay, and flooding attacks
- Cloud audit events such as accepted messages and blocked-message reports

## How to Run
Run this after normal traffic or attack simulations:

```bash
python -m reports.summary_report
```

## Why It Helps
The report gives a quick view of system behavior. Instead of reading every log
line manually, you can see how many messages were accepted and how many attack
events were blocked.
