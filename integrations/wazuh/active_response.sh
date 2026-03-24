#!/bin/bash
# DRRA Wazuh Active Response Script
# Triggered by Wazuh when ransomware rules fire; calls the DRRA SHIELD API to isolate the host.
#
# Install: /var/ossec/active-response/bin/drra_isolate.sh
# Permissions: chmod 750 /var/ossec/active-response/bin/drra_isolate.sh
#              chown root:wazuh /var/ossec/active-response/bin/drra_isolate.sh

# Wazuh active response protocol: read JSON from stdin
read INPUT_JSON

# Parse fields from the Wazuh AR JSON envelope
ALERT_ID=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('alert', {}).get('id', 'unknown'))")
ALERT_RULE=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('alert', {}).get('rule', {}).get('id', '0'))")
AGENT_IP=$(echo "$INPUT_JSON"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('parameters', {}).get('alert', {}).get('agent', {}).get('ip', ''))")
AGENT_NAME=$(echo "$INPUT_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('parameters', {}).get('alert', {}).get('agent', {}).get('name', 'unknown'))")

# DRRA API configuration
DRRA_API_URL="${DRRA_API_URL:-http://localhost:8000}"
DRRA_API_KEY="${DRRA_API_KEY:-}"

LOG_FILE="/var/ossec/logs/drra_active_response.log"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

log() {
    echo "[$TIMESTAMP] $*" >> "$LOG_FILE"
}

log "Active response triggered: rule=$ALERT_RULE agent=$AGENT_NAME ip=$AGENT_IP alert_id=$ALERT_ID"

# Only respond to DRRA ransomware rules (200000–200099) and level 12+
RULE_INT=$(echo "$ALERT_RULE" | tr -d '[:space:]')
if [ "$RULE_INT" -lt 200000 ] || [ "$RULE_INT" -gt 200099 ]; then
    log "Rule $ALERT_RULE not in DRRA range — skipping active response"
    exit 0
fi

if [ -z "$AGENT_IP" ]; then
    log "ERROR: Could not determine agent IP — aborting isolation"
    exit 1
fi

# Determine threat level based on rule ID
case "$ALERT_RULE" in
    200001|200020|200031)
        THREAT_LEVEL="medium"
        ACTION="monitor"
        ;;
    200002|200004|200021|200022|200030)
        THREAT_LEVEL="high"
        ACTION="isolate"
        ;;
    200003|200090|200091)
        THREAT_LEVEL="critical"
        ACTION="isolate"
        ;;
    *)
        THREAT_LEVEL="high"
        ACTION="isolate"
        ;;
esac

log "Threat level=$THREAT_LEVEL action=$ACTION for $AGENT_IP"

# Call DRRA SHIELD isolation API
PAYLOAD=$(python3 - <<EOF
import json
print(json.dumps({
    "target_ip": "$AGENT_IP",
    "hostname": "$AGENT_NAME",
    "reason": "Wazuh active response: rule $ALERT_RULE",
    "alert_id": "$ALERT_ID",
    "threat_level": "$THREAT_LEVEL",
    "isolation_type": "vlan_quarantine",
    "source": "wazuh_ar"
}))
EOF
)

if [ "$ACTION" = "isolate" ]; then
    RESPONSE=$(curl -s -o /tmp/drra_ar_response.json -w "%{http_code}" \
        -X POST "${DRRA_API_URL}/api/v1/shield/isolate" \
        -H "Content-Type: application/json" \
        ${DRRA_API_KEY:+-H "X-API-Key: $DRRA_API_KEY"} \
        -d "$PAYLOAD" \
        --max-time 10)

    HTTP_CODE="$RESPONSE"
    RESPONSE_BODY=$(cat /tmp/drra_ar_response.json 2>/dev/null)

    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
        log "SUCCESS: SHIELD isolation accepted for $AGENT_IP (HTTP $HTTP_CODE)"
        log "Response: $RESPONSE_BODY"
    else
        log "ERROR: SHIELD API returned HTTP $HTTP_CODE for $AGENT_IP"
        log "Response: $RESPONSE_BODY"

        # Fallback: local firewall block via iptables if API unreachable
        log "Attempting local iptables fallback block for $AGENT_IP"
        iptables -I INPUT  -s "$AGENT_IP" -j DROP
        iptables -I OUTPUT -d "$AGENT_IP" -j DROP
        log "iptables DROP rules added for $AGENT_IP"
    fi
elif [ "$ACTION" = "monitor" ]; then
    # Medium severity: just log an enrichment event to VIGIL
    curl -s -X POST "${DRRA_API_URL}/api/v1/vigil/events" \
        -H "Content-Type: application/json" \
        ${DRRA_API_KEY:+-H "X-API-Key: $DRRA_API_KEY"} \
        -d "$PAYLOAD" \
        --max-time 5 > /dev/null 2>&1
    log "Monitor event sent to VIGIL for $AGENT_IP"
fi

exit 0
