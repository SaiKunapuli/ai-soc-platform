# Wazuh lab — single-node stack on Windows (Docker Desktop / WSL2)

Runbook for Phase 1. Uses the **official** `wazuh/wazuh-docker` deployment rather than a
hand-rolled compose file — the official stack handles cert generation and component wiring.

## Prerequisites

- Docker Desktop with the WSL2 backend
- ~8 GB RAM free for the stack
- Inside WSL2, the indexer needs a higher `vm.max_map_count`:

  ```powershell
  wsl -d docker-desktop sysctl -w vm.max_map_count=262144
  ```

  (Re-run after reboots, or persist it in `%UserProfile%\.wslconfig` / the distro's sysctl config.)

## 1. Deploy the server stack

```powershell
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker
git checkout <latest 4.x release tag>   # check https://github.com/wazuh/wazuh-docker/releases
cd single-node

# one-time: generate the self-signed certs
docker compose -f generate-indexer-certs.yml run --rm generator

docker compose up -d
```

Wazuh dashboard: https://localhost — default `admin` / password from the repo's `docker-compose.yml`
(change it, then update `.env` in this repo).

## 2. Enable the archives index (REQUIRED for the ML layer)

By default only rule-matched events are indexed (`wazuh-alerts-*`). Behavioral baselines need
**all** events. In the wazuh manager container, edit `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <global>
    <logall_json>yes</logall_json>
  </global>
</ossec_config>
```

Then enable the `archives` filebeat module and restart the manager. Verify a `wazuh-archives-*`
index appears in the indexer.

⚠️ Archives grow fast. This is fine for a lab; add an index lifecycle policy if disk fills up.

## 3. Instrument this Windows machine (the monitored endpoint)

### Sysmon

```powershell
# from an elevated prompt — Sysinternals Sysmon + SwiftOnSecurity config
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip -DestinationPath Sysmon
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig.xml
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Wazuh agent

Download the Windows agent MSI from the Wazuh docs (match the server version), install with
`WAZUH_MANAGER=localhost` (the Docker-published manager port), then make sure the agent's
`ossec.conf` collects the Sysmon channel:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent service and confirm it shows **active** in the Wazuh dashboard.

## 4. Verify end to end

1. Open PowerShell, run something noisy: `whoami /all; systeminfo`
2. Wazuh dashboard → Security events → filter by your agent — Sysmon process-creation
   events should appear within seconds.
3. Query the indexer directly (this is what `aisoc.ingestion` does):

   ```powershell
   curl.exe -k -u admin:<password> "https://localhost:9200/wazuh-alerts-*/_search?size=1&pretty"
   ```

**Phase 1 exit criterion:** an Atomic Red Team run (see [../simulations/README.md](../simulations/README.md))
lands as visible Wazuh alerts, and raw archive events are queryable.
