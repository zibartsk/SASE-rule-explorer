#!/usr/bin/env bash
# Fetches firewall rules for a given network name whose source includes a
# given group name. Read-only: imports the network's firewall policy into a
# throwaway Terraform state entry to read it via `terraform show -json`, then
# always removes that state entry + its temp config on exit — nothing is ever
# applied, so the real firewall policy is never modified.
#
# Usage: ./fetch-firewall-rules.sh <network_name> <group_name>
# Requires: terraform, jq, and CHECKPOINT_SASE_API_KEY/BASE_URL in .env.

set -euo pipefail
cd "$(dirname "$0")"

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <network_name> <group_name>" >&2
  exit 1
fi
network_name="$1"
group_name="$2"

set -a
source <(sed 's/\r$//' .env)
set +a

resource_addr="checkpointsase_firewall_policy.tmp_inspect_$$"
tmp_tf_file="_inspect_tmp_$$.tf"

cleanup() {
  terraform state rm -lock=false "$resource_addr" >/dev/null 2>&1 || true
  rm -f "$tmp_tf_file"
}
trap cleanup EXIT

# `terraform console` reads the existing state, not live data — refresh first
# so a switch to a different tenant's API key is actually reflected here.
terraform apply -refresh-only -lock=false -auto-approve >/dev/null

network_id=$(terraform console <<EOF | tr -d '"'
try([for n in data.checkpointsase_standard_networks.all.networks : n.id if n.name == "${network_name}"][0], "")
EOF
)
if [[ -z "$network_id" ]]; then
  echo "No standard network named '${network_name}' found." >&2
  exit 1
fi

group_id=$(terraform console <<EOF | tr -d '"'
try([for g in data.checkpointsase_groups.all.data : g.id if g.name == "${group_name}"][0], "")
EOF
)
if [[ -z "$group_id" ]]; then
  echo "No group named '${group_name}' found." >&2
  exit 1
fi

cat > "$tmp_tf_file" <<EOF
# Temporary, read-only inspection resource — removed by fetch-firewall-rules.sh on exit.
resource "checkpointsase_firewall_policy" "tmp_inspect_$$" {
  network_id = "${network_id}"
  enabled    = true
  allowed    = false
}
EOF

terraform import -lock=false "$resource_addr" "$network_id" >/dev/null

state_json=$(terraform show -json)

# Map address/service object IDs to names so rules print names, not IDs.
# Built-in/system objects (e.g. default services) aren't in either shared
# library and stay as their raw ID — there's no name available for them.
addr_names=$(echo "$state_json" | jq -c '
  [.values.root_module.resources[]
   | select(.address == "data.checkpointsase_object_addresses.all")
   | .values.object_addresses[]
   | {(.id): .name}] | add // {}
')
service_names=$(echo "$state_json" | jq -c '
  [.values.root_module.resources[]
   | select(.address == "data.checkpointsase_object_services.all")
   | .values.object_services[]
   | {(.id): .name}] | add // {}
')

rows=$(echo "$state_json" | jq -c --arg addr "$resource_addr" --arg gid "$group_id" --argjson anames "$addr_names" --argjson snames "$service_names" '
  .values.root_module.resources[]
  | select(.address == $addr)
  | .values.policy_rules[]
  | select((.sources[0].groups // []) | index($gid))
  | {
      rule: .name,
      action: (if .allowed then "Accept" else "Drop" end),
      services: (.services // ["any"] | map($snames[.] // .)),
      destinations: ((.destinations[0].addresses // ["any"]) | map($anames[.] // .))
    }
')

if [[ -z "$rows" ]]; then
  echo "No rules found on '${network_name}' with source group '${group_name}'."
else
  echo "$rows" | jq -r '"\(.rule) | \(.action) | services=\(.services | join(",")) | destinations=\(.destinations | join(","))"'
fi

html_file="firewall-rules_$$.html"
{
  cat <<HTML
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Firewall rules — ${network_name}</title>
<style>
  :root {
    color-scheme: light dark;
    --accent: #2563eb;
    --allow: #15803d;
    --allow-bg: #dcfce7;
    --drop: #b91c1c;
    --drop-bg: #fee2e2;
    --border: #e2e8f0;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 2.5rem 1.5rem;
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #f8fafc;
    color: #0f172a;
  }
  .card {
    max-width: 900px;
    margin: 0 auto;
    background: #fff;
    border: 1px solid var(--border);
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,.06), 0 1px 2px rgba(0,0,0,.04);
    overflow: hidden;
  }
  .card-header {
    padding: 1.5rem 1.75rem;
    border-bottom: 1px solid var(--border);
  }
  .card-header h1 {
    margin: 0 0 .35rem;
    font-size: 1.25rem;
  }
  .card-header p {
    margin: 0;
    color: #64748b;
    font-size: .9rem;
  }
  .card-header .badge {
    display: inline-block;
    margin-top: .6rem;
    padding: .2rem .6rem;
    border-radius: 999px;
    background: #eef2ff;
    color: var(--accent);
    font-size: .78rem;
    font-weight: 600;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: .9rem;
  }
  th, td {
    text-align: left;
    padding: .75rem 1.75rem;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }
  th {
    background: #f1f5f9;
    color: #475569;
    font-size: .75rem;
    text-transform: uppercase;
    letter-spacing: .04em;
  }
  th:nth-child(3), th:nth-child(4) { width: 32%; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  .action {
    display: inline-block;
    padding: .15rem .55rem;
    border-radius: 6px;
    font-weight: 600;
    font-size: .8rem;
  }
  .action.accept { color: var(--allow); background: var(--allow-bg); }
  .action.drop { color: var(--drop); background: var(--drop-bg); }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: .3rem;
  }
  .chip {
    display: inline-block;
    max-width: 100%;
    padding: .1rem .5rem;
    border-radius: 999px;
    background: #f1f5f9;
    color: #334155;
    font-size: .78rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .empty {
    padding: 2.5rem 1.75rem;
    text-align: center;
    color: #64748b;
  }
  .footer {
    padding: 1rem 1.75rem;
    font-size: .75rem;
    color: #94a3b8;
    border-top: 1px solid var(--border);
  }
</style>
</head>
<body>
<div class="card">
  <div class="card-header">
    <h1>Firewall rules</h1>
    <p>Network <strong>${network_name}</strong> &middot; source group <strong>${group_name}</strong></p>
    <span class="badge">$(echo "$rows" | grep -c . 2>/dev/null || echo 0) matching rule(s)</span>
  </div>
HTML
  if [[ -z "$rows" ]]; then
    echo '  <div class="empty">No rules found.</div>'
  else
    echo '  <table>'
    echo '    <tr><th>Rule</th><th>Action</th><th>Services</th><th>Destinations</th></tr>'
    echo "$rows" | jq -r '
      def chips: "<div class=\"chips\">" + (map("<span class=\"chip\" title=\"\(. | @html)\">\(. | @html)</span>") | join("")) + "</div>";
      "    <tr><td>\(.rule | @html)</td><td><span class=\"action \(.action | ascii_downcase)\">\(.action | @html)</span></td>" +
      "<td>\(.services | chips)</td>" +
      "<td>\(.destinations | chips)</td></tr>"
    '
    echo '  </table>'
  fi
  cat <<HTML
  <div class="footer">Generated $(date -u +"%Y-%m-%d %H:%M UTC") by fetch-firewall-rules.sh</div>
</div>
</body>
</html>
HTML
} > "$html_file"

echo
echo "HTML report written to ${html_file}"
