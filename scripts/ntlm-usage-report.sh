#!/usr/bin/env bash

set -euo pipefail

ARCHIVE="${1:-/var/ossec/logs/archives/archives.json}"

if [[ ! -r "$ARCHIVE" ]]; then
    echo "ERROR: Cannot read archive: $ARCHIVE" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required." >&2
    exit 1
fi

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT

echo "WSF NTLM Usage / Posture Report"
echo "Source: $ARCHIVE"
echo "Generated: $(date --iso-8601=seconds)"
echo

# Extract successful Windows network logons authenticated using NTLM.
#
# Columns:
#   target_server
#   domain
#   user
#   workstation
#   source_ip
#   logon_type
#   ntlm_version

jq -Rr '
    fromjson?
    | select(.data.win.system.eventID == "4624")
    | select(.data.win.eventdata.authenticationPackageName == "NTLM")
    | [
        (.agent.name // "-"),
        (.data.win.eventdata.targetDomainName // "-"),
        (.data.win.eventdata.targetUserName // "-"),
        (.data.win.eventdata.workstationName // "-"),
        (.data.win.eventdata.ipAddress // "-"),
        (.data.win.eventdata.logonType // "-"),
        (.data.win.eventdata.lmPackageName // "-")
      ]
    | @tsv
' "$ARCHIVE" > "$TMP_FILE"


echo "===== NTLM VERSION SUMMARY - ALL NETWORK LOGONS ====="

awk -F '\t' '
    $6 == "3" {
        version=$7
        count[version]++
    }
    END {
        for (version in count)
            printf "%8d  %s\n", count[version], version
    }
' "$TMP_FILE" |
sort -nr

echo


echo "===== NTLM VERSION SUMMARY - AUTHENTICATED ====="

awk -F '\t' '
    $6 == "3" &&
    $3 != "ANONYMOUS LOGON" {
        version=$7
        count[version]++
    }
    END {
        for (version in count)
            printf "%8d  %s\n", count[version], version
    }
' "$TMP_FILE" |
sort -nr

echo


echo "===== NTLM VERSION SUMMARY - ANONYMOUS ====="

awk -F '\t' '
    $6 == "3" &&
    $3 == "ANONYMOUS LOGON" {
        version=$7
        count[version]++
    }
    END {
        for (version in count)
            printf "%8d  %s\n", count[version], version
    }
' "$TMP_FILE" |
sort -nr

echo

echo "===== AUTHENTICATED NTLMv1 NETWORK LOGONS ====="

awk -F '\t' '
    $6 == "3" &&
    $7 == "NTLM V1" &&
    $3 != "ANONYMOUS LOGON" {
        print
    }
' "$TMP_FILE" |
sort |
uniq -c |
sort -nr |
head -50

echo


echo "===== TOP NTLMv2 DEPENDENCIES ====="
echo "COUNT  USER  WORKSTATION  SOURCE_IP  TARGET_SERVER"

awk -F '\t' '
    $6 == "3" &&
    $7 == "NTLM V2" &&
    $3 != "ANONYMOUS LOGON" &&
    $3 !~ /^HealthMailbox/ {
        print $3 "\t" $4 "\t" $5 "\t" $1
    }
' "$TMP_FILE" |
sort |
uniq -c |
sort -nr |
head -50

echo


echo "===== NTLMv2 MACHINE ACCOUNT DEPENDENCIES ====="
echo "COUNT  ACCOUNT  WORKSTATION  SOURCE_IP  TARGET_SERVER"

awk -F '\t' '
    $6 == "3" &&
    $7 == "NTLM V2" &&
    $3 ~ /\$$/ {
        print $3 "\t" $4 "\t" $5 "\t" $1
    }
' "$TMP_FILE" |
sort |
uniq -c |
sort -nr |
head -50

echo


echo "===== ANONYMOUS NTLM LOGONS ====="
echo "COUNT  WORKSTATION  SOURCE_IP  TARGET_SERVER  VERSION"

awk -F '\t' '
    $6 == "3" &&
    $3 == "ANONYMOUS LOGON" {
        print $4 "\t" $5 "\t" $1 "\t" $7
    }
' "$TMP_FILE" |
sort |
uniq -c |
sort -nr |
head -50

echo


echo "===== NTLM TARGET SERVERS ====="
echo "COUNT  TARGET_SERVER  VERSION"

awk -F '\t' '
    $6 == "3" {
        print $1 "\t" $7
    }
' "$TMP_FILE" |
sort |
uniq -c |
sort -nr

