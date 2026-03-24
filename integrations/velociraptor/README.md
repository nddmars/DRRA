# DRRA Velociraptor Integration

Digital forensics and live endpoint response artifacts for ransomware incidents.

## Artifacts

| Artifact | Type | Purpose |
|----------|------|---------|
| `DRRA.Ransomware.ForensicCollection` | CLIENT | On-demand forensic collection post-isolation |
| `DRRA.Ransomware.ActiveHunt` | CLIENT_EVENT | Continuous real-time ransomware monitoring |

## Import

```bash
# Velociraptor GUI: Server Artifacts → Upload Artifact
# Or via CLI:
velociraptor --config server.config.yaml artifacts upload DRRA.Ransomware.ForensicCollection.yaml
velociraptor --config server.config.yaml artifacts upload DRRA.Ransomware.ActiveHunt.yaml
```

## ForensicCollection — Run After Isolation

Collects: processes, network connections, encrypted file inventory, ransom notes, VSS status, registry persistence, prefetch, PowerShell history, and DRRA telemetry.

```bash
# Target a specific host
velociraptor query "SELECT * FROM Artifact.DRRA.Ransomware.ForensicCollection(TargetPath='C:\\')" \
  --org_id root --add_labels compromised-host-01
```

## ActiveHunt — Continuous Monitoring

Streams high-entropy writes, mass modifications, VSS deletions, and LSASS access to DRRA VIGIL in real-time.

```bash
# Deploy as a fleet-wide hunt
velociraptor hunt --artifact DRRA.Ransomware.ActiveHunt \
  --parameter DRRAApiUrl=http://drra-backend:8000 \
  --condition "true"   # all endpoints
```
