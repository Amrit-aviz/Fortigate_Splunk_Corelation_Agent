# Vodafone Agent (FortiGate + Splunk Correlation) — NCP Playground

This agent answers the **primary PRD use cases** for Vodafone Fiji by querying Splunk for FortiGate logs and correlating:
1) Recent config changes (firewall policy edits)
2) Admin login failures
3) Internet access denied (forward traffic denies) — works once you connect a LAN client behind the FortiGate and generate forward traffic logs.

## 0) Prerequisites
- You already have FortiGate logs flowing into Splunk (UDP 5514 syslog).
- You have `ncp` CLI installed (same as other agents workflow - SDK Agent Guide).
- You have a Splunk token for the Splunk **management API** (usually port 8089).

## 1) Setup
```bash
unzip vodafone-agent.zip
cd vodafone-agent
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 2) Configure environment variables
Option A (recommended): export variables in your terminal:
```bash
export SPLUNK_URL="https://10.4.4.152:8089"
export SPLUNK_TOKEN="YOUR_SPLUNK_TOKEN"
export SPLUNK_VERIFY_SSL="false"
export SPLUNK_SOURCE="udp:5514"
export SPLUNK_SOURCETYPE="fgt_log"
export FGT_HOST="10.20.11.29"
```

Option B: create a `.env` file from `.env.example` and export them using your shell.

## 3) Validate + package + playground
```bash
ncp validate .
ncp package .
ncp playground .
```

## 4) Try these queries in Playground
### Use Case 1 — Config changes
- "What configuration changes were made on FortiGate in the last 24 hours?"

### Use Case 2 — Login failure
- "Why is user superadmin unable to connect to FortiGate?"
- "Why is user john.doe unable to connect to FortiGate?"

### Use Case 3 — Internet denied (needs LAN client later)
- "Why can’t user 192.168.1.10 access the internet?"

If your LAN client is not connected yet, the agent will explain that forward-traffic denies are not present yet.
Once you connect a laptop/VM behind FortiGate and generate traffic, this will work without code changes.

## Notes
- Config-change detection matches your real lab event:
  `type="event" subtype="system" logdesc="Object attribute configured" cfgpath="firewall.policy" action="Edit"`
- Login-failure detection matches your real lab stats:
  `type="event" subtype="system" action="login" logdesc="Admin login failed"`
