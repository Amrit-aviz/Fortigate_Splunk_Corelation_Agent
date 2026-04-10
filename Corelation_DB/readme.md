# Vodafone FortiGate Agent (Direct DB Ingestion)

This agent answers FortiGate questions (login failures, config changes, denied traffic, etc.) **by querying Postgres** where syslog is ingested into the `syslog_events` table.

## Data flow

FortiGate → Syslog (UDP/514) → `ncp-syslog-collector` → Kafka topic `SOURCE_SYSLOG_UPDATES` → Kafka topic `OUTPUT_SYSLOG_UPDATES` → JDBC sink (`OUTPUT_SYSLOG_UPDATES` connector) → Postgres (`metrics.syslog_events`)

## Required runtime env vars

Set these in the NCP platform runtime environment:

- `SYSLOG_DB_HOST` (example: `10.4.4.174`)
- `SYSLOG_DB_PORT` (default: `5432`)
- `SYSLOG_DB_NAME` (default: `metrics`)
- `SYSLOG_DB_USER` (default: `postgres`)
- `SYSLOG_DB_PASSWORD` (**required**)
- `SYSLOG_DB_SSLMODE` (default: `prefer`)
- `FGT_HOST` (optional; if set, tools will filter to that FortiGate IP)

See `.env.example`.

## Example questions

- “List admin login failures in the last 24 hours”
- “Did anyone change configuration today?”
- “Why can’t 10.0.1.5 access the internet?”
- “Show denied traffic for 10.0.1.5 in the last 2 hours”

## Quick ingestion validation (Docker)

Run these on the NCP VM:

1) **Verify syslog collector container is up**
```bash
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep -i syslog
```

2) **Watch raw syslog arriving to the syslog collector**
```bash
sudo docker logs -f --tail 50 ncp-syslog-collector
```

3) **Confirm Kafka is receiving syslog (source topic)**
```bash
sudo docker exec -it ncp-broker bash -lc 'kafka-console-consumer --bootstrap-server localhost:9092 --topic SOURCE_SYSLOG_UPDATES --max-messages 5 --timeout-ms 10000'
```

4) **Confirm Kafka is producing transformed syslog (output topic)**
```bash
sudo docker exec -it ncp-broker bash -lc 'kafka-console-consumer --bootstrap-server localhost:9092 --topic OUTPUT_SYSLOG_UPDATES --max-messages 5 --timeout-ms 10000'
```

5) **Confirm the JDBC sink connector is running**
```bash
sudo docker exec -it ncp-connect bash -lc 'curl -s http://localhost:8083/connectors/OUTPUT_SYSLOG_UPDATES/status'
```

6) **Confirm Postgres has rows in `syslog_events`**
```bash
sudo docker exec -it ncp-collector-db bash -lc 'psql -U postgres -d metrics -c "select count(*) from syslog_events;"'
sudo docker exec -it ncp-collector-db bash -lc 'psql -U postgres -d metrics -c "select ts, host, left(message,120) as msg from syslog_events order by ts desc limit 10;"'
```

## Build & Deploy

```bash
ncp validate .
ncp package .
ncp deploy <generated>.ncp
```
