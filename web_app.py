#!/usr/bin/env python3
"""Local web UI for browsing SASE firewall rules by network and source group."""

import json
import os
import signal
import subprocess
import sys
import threading
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

ROOT = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(ROOT, ".env")
DEFAULT_PORT = int(os.environ.get("PORT", "8080"))
TERRAFORM_LOCK = threading.Lock()


def load_dotenv(path):
    env = os.environ.copy()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    os.environ.update({k: v for k, v in env.items() if v is not None})


def run_terraform(args, input_text=None):
    load_dotenv(ENV_FILE)

    normalized = list(args)
    if not normalized:
        raise ValueError("Terraform command arguments are required")

    if normalized[0] in {"console", "show"}:
        command = ["terraform", *normalized]
    elif normalized[0] in {"apply", "import", "state", "plan", "destroy", "refresh", "validate"}:
        command = ["terraform", normalized[0], "-lock=false", *normalized[1:]]
    else:
        command = ["terraform", *normalized]

    with TERRAFORM_LOCK:
        proc = subprocess.run(
            command,
            cwd=ROOT,
            input=input_text,
            text=True,
            capture_output=True,
            env=os.environ.copy(),
        )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "terraform command failed").strip()
        raise RuntimeError(detail)
    return proc.stdout.strip()


def refresh_state():
    run_terraform(["apply", "-refresh-only", "-auto-approve"]) 


def fetch_json_list(terraform_expr):
    data = run_terraform(["console"], input_text=f"{terraform_expr}\n")
    if not data or data in {"null", "\"\""}:
        return []
    try:
        payload = json.loads(data)
        if isinstance(payload, str):
            payload = json.loads(payload)
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else []


def list_networks():
    payload = fetch_json_list(
        "jsonencode([for n in data.checkpointsase_standard_networks.all.networks : {id = n.id, name = n.name}])"
    )
    return sorted(payload, key=lambda item: str(item.get("name", "")).lower())


def list_groups():
    payload = fetch_json_list(
        "jsonencode([for g in data.checkpointsase_groups.all.data : {id = g.id, name = g.name}])"
    )
    return sorted(payload, key=lambda item: str(item.get("name", "")).lower())


def get_network_id(name):
    for candidate in list_networks():
        if candidate.get("name") == name:
            return candidate.get("id")
    raise ValueError(f"No standard network named '{name}' found.")


def get_group_id(name):
    for candidate in list_groups():
        if candidate.get("name") == name:
            return candidate.get("id")
    raise ValueError(f"No group named '{name}' found.")


def fetch_policy_rules(network_name, group_name):
    refresh_state()
    network_id = get_network_id(network_name)
    group_id = get_group_id(group_name)

    temp_name = f"_inspect_tmp_{uuid4().hex}.tf"
    temp_path = os.path.join(ROOT, temp_name)
    temp_label = f"tmp_inspect_{uuid4().hex}"
    resource_addr = f"checkpointsase_firewall_policy.{temp_label}"

    try:
        with open(temp_path, "w", encoding="utf-8") as handle:
            handle.write(
                "resource \"checkpointsase_firewall_policy\" \"" + temp_label + "\" {\n"
                f"  network_id = \"{network_id}\"\n"
                "  enabled    = true\n"
                "  allowed    = false\n"
                "}\n"
            )

        run_terraform(["import", resource_addr, network_id])
        state_json = json.loads(run_terraform(["show", "-json"]))

        def collect_root_resources(module):
            resources = module.get("resources", [])
            for child in module.get("child_modules", []):
                resources.extend(collect_root_resources(child))
            return resources

        resources = collect_root_resources(state_json.get("values", {}).get("root_module", {}))

        address_names = {}
        service_names = {}
        for resource in resources:
            address = resource.get("address")
            values = resource.get("values", {})
            if address == "data.checkpointsase_object_addresses.all":
                for item in values.get("object_addresses", []):
                    key = item.get("id")
                    if key:
                        address_names[key] = item.get("name")
            elif address == "data.checkpointsase_object_services.all":
                for item in values.get("object_services", []):
                    key = item.get("id")
                    if key:
                        service_names[key] = item.get("name")

        rows = []
        for resource in resources:
            if resource.get("address") != resource_addr:
                continue
            for rule in resource.get("values", {}).get("policy_rules", []):
                sources = rule.get("sources") or []
                if not sources:
                    continue
                groups = sources[0].get("groups") or []
                if group_id not in groups:
                    continue

                services = rule.get("services") or ["any"]
                destinations = (rule.get("destinations") or [{}])[0].get("addresses") or ["any"]
                rows.append(
                    {
                        "rule": rule.get("name") or "(unnamed)",
                        "action": "Accept" if rule.get("allowed") else "Drop",
                        "services": [service_names.get(item, item) for item in services],
                        "destinations": [address_names.get(item, item) for item in destinations],
                    }
                )

        return rows
    finally:
        try:
            run_terraform(["state", "rm", resource_addr])
        except Exception:
            pass
        try:
            os.remove(temp_path)
        except FileNotFoundError:
            pass


HTML_PAGE = """<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
  <title>SASE Firewall Rule Explorer</title>
  <style>
    :root {
      --bg: #f8fafc;
      --panel: #ffffff;
      --card: #ffffff;
      --border: #dfe7f1;
      --muted: #64748b;
      --text: #0f172a;
      --accent: #2563eb;
      --accent-soft: #eef2ff;
      --accept: #15803d;
      --accept-soft: #dcfce7;
      --drop: #b91c1c;
      --drop-soft: #fee2e2;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: -apple-system, Segoe UI, sans-serif;
      background: var(--bg); color: var(--text);
    }
    .shell {
      width: min(100vw - 24px, 1800px);
      margin: 24px auto;
      padding: 0;
    }
    .panel {
      background: var(--panel); border: 1px solid var(--border);
      border-radius: 16px; box-shadow: 0 8px 26px rgba(15,23,42,.06); overflow: hidden;
    }
    .header {
      position: sticky;
      top: 0;
      z-index: 10;
      padding: 22px 24px;
      border-bottom: 1px solid var(--border);
      background: linear-gradient(180deg, #fff, #f8fafc);
    }
    .header h1 { margin: 0; font-size: 1.6rem; }
    .header p { margin: 8px 0 0; color: var(--muted); }
    .filters {
      display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px; padding: 24px; background: #fff; border-bottom: 1px solid var(--border);
    }
    label { display: block; font-weight: 600; margin-bottom: 8px; }
    select, button {
      width: 100%; border-radius: 10px; font: inherit; padding: 11px 12px;
    }
    select {
      border: 1px solid var(--border); background: #fff; color: var(--text);
    }
    button {
      background: var(--accent); color: white; border: none; cursor: pointer;
      font-weight: 600; margin-top: 27px; transition: filter .15s ease;
    }
    button:hover { filter: brightness(1.05); }
    button:disabled { opacity: .6; cursor: not-allowed; }
    .content {
      padding: 24px 24px 0;
      max-height: calc(100vh - 210px);
      overflow: auto;
      position: relative;
    }
    .content table {
      margin-top: 0;
    }
    .status {
      margin: 0 0 18px; padding: 10px 12px; border-radius: 10px; background: #f8fafc;
      border: 1px solid var(--border); color: var(--muted);
      position: sticky;
      top: 124px;
      z-index: 8;
    }
    .table-shell {
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      background: var(--panel);
    }
    .table-header {
      display: grid;
      grid-template-columns: 15% 5% 35% 45%;
      background: #f1f5f9;
      color: #475569;
      font-size: .73rem;
      letter-spacing: .04em;
      text-transform: uppercase;
      font-weight: 700;
      position: sticky;
      top: 0;
      z-index: 20;
      border-bottom: 1px solid var(--border);
    }
    .table-header > div {
      padding: 12px 14px;
      border-right: 1px solid var(--border);
    }
    .table-header > div:last-child {
      border-right: none;
    }
    .table-scroll {
      max-height: calc(100vh - 310px);
      overflow: auto;
    }
    table {
      width: 100%; border-collapse: collapse; font-size: .95rem;
      table-layout: fixed;
    }
    th, td {
      text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--border);
      vertical-align: top;
      word-wrap: break-word;
      overflow-wrap: anywhere;
    }
    .action {
      display: inline-block; padding: 4px 8px; border-radius: 999px; font-weight: 700; font-size: .78rem;
      white-space: nowrap;
    }
    .action.accept { color: var(--accept); background: var(--accept-soft); }
    .action.drop { color: var(--drop); background: var(--drop-soft); }
    .pill-wrap { display: flex; flex-wrap: wrap; gap: 6px; }
    .pill {
      max-width: 100%; display: inline-block; padding: 4px 8px; border-radius: 999px; background: #f1f5f9;
      color: #334155; font-size: .76rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    th:nth-child(1), td:nth-child(1) { width: 15%; }
    th:nth-child(2), td:nth-child(2) { width: 5%; }
    th:nth-child(3), td:nth-child(3) { width: 35%; }
    th:nth-child(4), td:nth-child(4) { width: 45%; }
    td:nth-child(1) {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .empty {
      padding: 32px 20px; text-align: center; color: var(--muted);
      border: 1px dashed var(--border); border-radius: 12px; background: #f8fafc;
    }
    @media (max-width: 680px) { .shell { padding: 0 10px; } }
  </style>
</head>
<body>
  <div class=\"shell\">
    <div class=\"panel\">
      <div class=\"header\">
        <h1>Firewall Rule Explorer</h1>
        <p>Look up rules by network and source group.</p>
      </div>
      <div class=\"filters\">
        <div>
          <label for=\"network\">Network</label>
          <select id=\"network\" aria-label=\"Network\"><option value=\"\">Loading…</option></select>
        </div>
        <div>
          <label for=\"group\">Source group</label>
          <select id=\"group\" aria-label=\"Source group\"><option value=\"\">Loading…</option></select>
        </div>
        <div>
          <button id=\"search\" type=\"button\">Fetch firewall rules</button>
        </div>
      </div>
      <div class=\"content\">
        <div id=\"status\" class=\"status\">Select a network and a group, then click the button.</div>
        <div id=\"results\"></div>
      </div>
    </div>
  </div>

  <script>
    const networkSelect = document.getElementById('network');
    const groupSelect = document.getElementById('group');
    const searchButton = document.getElementById('search');
    const statusEl = document.getElementById('status');
    const resultsEl = document.getElementById('results');

    function setStatus(message, isError = false) {
      statusEl.textContent = message || '';
      statusEl.style.display = message ? 'block' : 'none';
      statusEl.style.borderColor = isError ? '#fecaca' : '#dfe7f1';
      statusEl.style.background = isError ? '#fff1f2' : '#f8fafc';
      statusEl.style.color = isError ? '#991b1b' : '#64748b';
    }

    function renderEmpty(message) {
      resultsEl.innerHTML = '<div class="empty">' + message + '</div>';
    }

    function renderRows(rows) {
      if (!rows.length) {
        renderEmpty('No matching firewall rules were found for this network and source group.');
        return;
      }

      function renderPills(values) {
        return '<div class="pill-wrap">' + values.map(v => '<span class="pill" title="' + escapeHtml(String(v)) + '">' + escapeHtml(String(v)) + '</span>').join('') + '</div>';
      }

      const table = [
        '<div class="table-shell">',
        '<div class="table-header"><div>Rule</div><div>Action</div><div>Services</div><div>Destinations</div></div>',
        '<div class="table-scroll"><table>',
        ...rows.map(row => (
          '<tr>' +
          '<td>' + escapeHtml(String(row.rule || '')) + '</td>' +
          '<td><span class="action ' + (row.action === 'Accept' ? 'accept' : 'drop') + '">' + escapeHtml(String(row.action || '')) + '</span></td>' +
          '<td>' + renderPills(row.services || ['any']) + '</td>' +
          '<td>' + renderPills(row.destinations || ['any']) + '</td>' +
          '</tr>'
        )),
        '</table></div></div>'
      ];

      resultsEl.innerHTML = table.join('');
    }

    function escapeHtml(value) {
      return value
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    async function apiFetch(path) {
      const response = await fetch(path, { headers: { 'Accept': 'application/json' } });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || 'Request failed');
      }
      return payload;
    }

    async function loadOptions() {
      try {
        const networks = await apiFetch('/api/networks');
        const groups = await apiFetch('/api/groups');

        populateSelect(networkSelect, networks, 'Select a network');
        populateSelect(groupSelect, groups, 'Select a group');
        setStatus('Ready. Choose the network and group to inspect.');
      } catch (error) {
        setStatus('Unable to load network and group data: ' + error.message, true);
        renderEmpty('Please check the Terraform provider configuration and your .env values.');
      }
    }

    function populateSelect(select, items, placeholder) {
      select.innerHTML = '';
      const fallback = document.createElement('option');
      fallback.value = '';
      fallback.textContent = placeholder;
      select.appendChild(fallback);

      for (const item of items) {
        const option = document.createElement('option');
        option.value = item.name;
        option.textContent = item.name;
        select.appendChild(option);
      }
    }

    searchButton.addEventListener('click', async () => {
      const network = networkSelect.value;
      const group = groupSelect.value;
      if (!network || !group) {
        setStatus('Please select both a network and a source group.', true);
        renderEmpty('A network and a group are required.');
        return;
      }

      searchButton.disabled = true;
      setStatus('Querying firewall rules…');
      resultsEl.innerHTML = '';

      try {
        const rows = await apiFetch('/api/rules?network=' + encodeURIComponent(network) + '&group=' + encodeURIComponent(group));
        renderRows(rows);
        setStatus('');
      } catch (error) {
        setStatus('Query failed: ' + error.message, true);
        renderEmpty('The rule query could not complete.');
      } finally {
        searchButton.disabled = false;
      }
    });

    loadOptions();
  </script>
</body>
</html>
"""


class AppHandler(BaseHTTPRequestHandler):
    server_version = "SASEFirewallUI/1.0"

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        try:
            if path == '/':
                self.send_html(HTML_PAGE)
            elif path == '/api/networks':
                self.send_json(list_networks())
            elif path == '/api/groups':
                self.send_json(list_groups())
            elif path == '/api/rules':
                network_name = (query.get('network', [''])[0] or '').strip()
                group_name = (query.get('group', [''])[0] or '').strip()
                if not network_name or not group_name:
                    raise ValueError('network and group parameters are required')
                data = fetch_policy_rules(network_name, group_name)
                self.send_json(data)
            else:
                self.send_error(404, 'Not found')
        except ValueError as exc:
            self.send_json({'error': str(exc)}, status=400)
        except Exception as exc:
            self.send_json({'error': str(exc)}, status=500)

    def log_message(self, format, *args):
        return

    def send_html(self, page):
        body = page.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    load_dotenv(ENV_FILE)

    port = DEFAULT_PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Usage: {sys.argv[0]} [port]", file=sys.stderr)
            sys.exit(2)

    server = ThreadingHTTPServer(("0.0.0.0", port), AppHandler)
    print(f"SASE firewall UI running on http://0.0.0.0:{port}")

    def shutdown(signum, frame):
        print("Shutting down web server...")
        server.shutdown()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
