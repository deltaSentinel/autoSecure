#!/usr/bin/env bash
# gen_real_data.sh — AutoSecure real-data generator
#
# Usage:
#   REPLICAS=3 CONCURRENCY=4 ./gen_real_data.sh [OUTPUT_DIR]
set -euo pipefail

TEMPLATE_ID=9000
START_VMID=9100
REPLICAS="${REPLICAS:-3}"
CONCURRENCY="${CONCURRENCY:-4}"
OUT="${1:-./real_out}"

# Worlds matching synth_dataset.py misconfig-world keys.
WORLDS=(M01 M02 M03 M04 M05 M06 M07 M08 M09 M10 M11 M12 CLEAN)

inject() {
  local vmid=$1 world=$2
  case "$world" in
    M01)  # ssh permit_root_login
      pct exec "$vmid" -- sed -i \
        's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
      ;;
    M05)  # world-writable directories
      pct exec "$vmid" -- bash -c \
        'mkdir -p /opt/share /srv/inbox && chmod -R a+w /opt/share /srv/inbox'
      ;;
    M12)  # world-writable /etc files
      pct exec "$vmid" -- bash -c 'chmod 666 /etc/hosts /etc/motd'
      ;;
    # ------------------------------------------------------------------
    # TODO: fill in M02-M11 by mirroring their definitions in
    # synth_dataset.py (e.g. which features each world injects), one
    # case arm per world. Keep injections minimal and faithful to the
    # synthetic semantics so labels transfer cleanly.
    # ------------------------------------------------------------------
    M02|M03|M04|M06|M07|M08|M09|M10|M11)
      echo "ERROR: world $world not implemented yet" >&2
      return 1
      ;;
    CLEAN)
      : ;;
  esac
}

wait_ready() {
  local vmid=$1 i
  for i in $(seq 1 30); do
    if pct exec "$vmid" -- true 2>/dev/null; then return 0; fi
    sleep 1
  done
  echo "ERROR: CT $vmid never became exec-ready" >&2
  return 1
}

harvest_one() {
  local world=$1 replica=$2 vmid=$3
  local dir="$OUT/$world"
  mkdir -p "$dir"

  pct clone "$TEMPLATE_ID" "$vmid" --hostname "as-${world}-${replica}" >/dev/null
  pct start "$vmid" >/dev/null
  wait_ready "$vmid"

  if ! inject "$vmid" "$world"; then
    pct destroy "$vmid" --purge >/dev/null 2>&1 || true
    return 1
  fi
  sleep 1  # let writes settle

  pct exec "$vmid" -- python3 /root/collect.py "$world" > "$dir/rep${replica}.json"

  pct destroy "$vmid" --purge >/dev/null   # destroy stops the CT first
  echo "  ✓ $world/rep${replica} (CT $vmid)"
}

main() {
  mkdir -p "$OUT"
  : > "$OUT/manifest.csv"
  echo "world,replica,vmid,label,file" >> "$OUT/manifest.csv"

  local vmid="$START_VMID"
  for world in "${WORLDS[@]}"; do
    for r in $(seq 1 "$REPLICAS"); do
      # cap parallelism
      while [ "$(jobs -rp | wc -l)" -ge "$CONCURRENCY" ]; do
        wait -n
      done
      local label="vulnerable"
      [ "$world" = "CLEAN" ] && label="clean"
      echo "$world,$r,$vmid,$label,$world/rep$r.json" >> "$OUT/manifest.csv"
      harvest_one "$world" "$r" "$vmid" &
      vmid=$((vmid + 1))
    done
  done
  wait
  echo "Done. Snapshots in $OUT"
}

main "$@"
