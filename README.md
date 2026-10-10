<div align="center">

# Action1 MCP Server

**Give Claude, ChatGPT or Codex read-only access to everything in your [Action1](https://www.action1.com) console.**

Managed endpoints, missing patches, vulnerabilities, software inventory, automations, reports and audit trail, through the
[Model Context Protocol](https://modelcontextprotocol.io).

[![PyPI](https://img.shields.io/pypi/v/action1-mcp-server?color=2563eb&label=PyPI)](https://pypi.org/project/action1-mcp-server/)
[![Python](https://img.shields.io/badge/python-3.10%2B-2563eb)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-16a34a)](LICENSE)
[![Read-only](https://img.shields.io/badge/access-read--only-16a34a)](#-security)
[![MCP](https://img.shields.io/badge/MCP-stdio-7c3aed)](https://modelcontextprotocol.io)

[Quick start](#-quick-start) · [What you can ask](#-what-you-can-ask) · [Available data](#-available-data) · [Tools](#-tools) · [Development](#-development)

</div>

---

## 🚀 Quick start

**1. Install**

```bash
pip install action1-mcp-server
```

**2. Get your API credentials**

In Action1, go to **Settings → API Credentials → Add API Credentials**, assign the **Viewer** role, and copy the **Client ID** (an `api-key-...@action1.com` address) and the **Client Secret**. The secret is shown only once.

**3. Connect your AI client**

<details open>
<summary><b>Claude Desktop</b></summary>

Edit `claude_desktop_config.json`. On Windows it is in `%APPDATA%\Claude\`; on macOS, in `~/Library/Application Support/Claude/`.

```json
{
  "mcpServers": {
    "action1": {
      "command": "action1-mcp-server",
      "env": {
        "ACTION1_CLIENT_ID": "api-key-...@action1.com",
        "ACTION1_CLIENT_SECRET": "your-client-secret"
      }
    }
  }
}
```

Then quit Claude Desktop completely (on Windows: tray icon → **Quit**) and open it again.

</details>

<details>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add action1 -e ACTION1_CLIENT_ID=api-key-...@action1.com -e ACTION1_CLIENT_SECRET=your-client-secret -- action1-mcp-server
```

</details>

<details>
<summary><b>Codex CLI, Codex IDE extension and ChatGPT desktop app</b></summary>

All three share the same configuration file, so you only need to set it up once.

Using the Codex CLI:

```bash
codex mcp add action1 --env ACTION1_CLIENT_ID=api-key-...@action1.com --env ACTION1_CLIENT_SECRET=your-client-secret -- action1-mcp-server
```

Or edit `~/.codex/config.toml` (on Windows: `%USERPROFILE%\.codex\config.toml`):

```toml
[mcp_servers.action1]
command = "action1-mcp-server"

[mcp_servers.action1.env]
ACTION1_CLIENT_ID = "api-key-...@action1.com"
ACTION1_CLIENT_SECRET = "your-client-secret"
```

In the ChatGPT desktop app you can also add it from **Settings → MCP servers → Add server → STDIO**, then select **Restart**.

> [!NOTE]
> ChatGPT on the web can't use this server: it doesn't read local configuration and only connects to remote MCP servers. Use the ChatGPT desktop app or Codex instead.

</details>

The data center region (North America, Europe, UK, Australia) is detected automatically on the first login. To pin it, set `ACTION1_REGION`.

**Updating**

```bash
pip install --upgrade action1-mcp-server
```

Restart your AI client afterwards. Your configuration stays the same.

## 💬 What you can ask

Ask in plain language, in any language:

- *"List the Action1 routes and what each one returns"*
- *"Give me an overview of the environment: endpoints, missing patches and vulnerabilities"*
- *"Which endpoints need a reboot or haven't checked in for more than 30 days?"*
- *"Show endpoint FINANCE-LAPTOP01 with its missing updates and CVEs"*
- *"List the critical CVEs in the CISA KEV catalog and which endpoints have them"*
- *"Which critical updates are past their SLA?"*
- *"How did last Friday's patch automation go on each endpoint?"*
- *"Who logged in to the console this week?"*

## 📦 Available data

All routes below were tested against a live Action1 account with a **Viewer** credential.

| Route | What it returns |
|---|---|
| `organizations`, `enterprise` | Organizations and enterprise details |
| `me`, `users` | The credential's user and the console users |
| `endpoints/managed/{orgId}` | Endpoints: status, last seen, IP, MAC, OS, hardware, logged-on user, agent version, groups, pending reboot, missing patch and CVE counts |
| `endpoints/managed/{orgId}/{id}/missing-updates` | Updates missing on one endpoint |
| `endpoints/groups/{orgId}` | Endpoint groups and their members |
| `vulnerabilities/{orgId}` | CVEs found on endpoints: CVSS, CISA KEV, affected software and versions, fixing update, remediation deadline and status |
| `vulnerabilities/{orgId}/{cveId}`, `CVE-descriptions/{cveId}` | CVE details, affected endpoints and documented compensating controls |
| `updates/{orgId}` | Missing OS and third-party patches: severity, approval, SLA, KB |
| `installed-software/{orgId}/data` | Software inventory, per organization or per endpoint |
| `software-repository/{orgId}` | Software repository packages and versions |
| `automations/schedules/{orgId}`, `automations/instances/{orgId}` | Scheduled automations, runs and per-endpoint results |
| `reports/all`, `reportdata/{orgId}/{reportId}/data` | Report catalog (~76 built-in reports) and report rows (CSV/HTML export) |
| `scripts/all`, `settings/all`, `setting-templates/all` | Script library and advanced settings |
| `audit/events` | Audit trail: logins, remote sessions, configuration changes, API calls |
| `subscription/*`, `roles`, `logs/{orgId}`, `endpoints/deployers/{orgId}`, `data-sources/all` | License, roles, diagnostic logs, Deployers and data sources (need a role above Viewer) |

Parameters, fields, required permissions and quirks for each route are documented in [`ENDPOINTS.md`](src/action1_mcp/ENDPOINTS.md) (in Portuguese). The map was built from Action1's official OpenAPI 3.1 specification, published at [app.action1.com/apidocs](https://app.action1.com/apidocs).

## 🧰 Tools

Tool names are in Portuguese; your AI assistant picks the right one from your request. In Action1, an *endpoint* is a managed computer, so the tools call computers *máquinas* and API paths *rotas*.

| Tool | Description |
|---|---|
| `action1_get` | Calls any `GET` route and passes every parameter through unchanged. `{orgId}` in the path is replaced with the default organization. With `paginar=True` it paginates automatically up to `max_registros`. `arquivo_saida` saves the full result to disk. |
| `listar_rotas` | Returns the API map (routes, parameters, fields, permissions, limits), so the assistant knows what it can request |
| `listar_organizacoes` | Lists the account's organizations (their IDs are the `orgId` used by the routes) |
| `listar_maquinas` | Lists endpoints with search and filters for status, pending reboot, patch and vulnerability status, OS and group |
| `buscar_maquina` | Fetches one endpoint by ID or name, with its missing updates, CVEs and, optionally, installed software |
| `listar_vulnerabilidades` | Lists CVEs by severity, remediation status, endpoint, publication date, CVE list or CISA KEV |
| `buscar_cve` | CVE details, affected endpoints, documented controls, and whether the CVE is present in the organization |
| `listar_atualizacoes` | Lists missing patches by severity, approval status and text |
| `listar_softwares` | Software inventory for the organization or for one endpoint |
| `listar_automacoes` | Scheduled automations, automation runs, or the per-endpoint result of one run |
| `consultar_relatorio` | Reads a report by name or ID; without a name, lists the report catalog |
| `listar_auditoria` | Audit trail for a date range, by event type or text |
| `resumo_ambiente` | Environment overview: endpoints by status, connection, OS, agent version and group; stale and pending-reboot endpoints; endpoints with the most missing patches and CVEs; patches by severity, approval and SLA; CVEs by severity, remediation status, KEV and product |

The resource `action1://rotas` exposes the full API map as Markdown.

<details>
<summary><b>Example of a generic call</b></summary>

```json
{
  "endpoint": "vulnerabilities/{orgId}",
  "params": {
    "score": "Critical",
    "remediation_status": "Overdue",
    "filter": "Chrome",
    "sortby": "-cvss_score"
  },
  "paginar": true,
  "max_registros": 500
}
```

</details>

## 🚦 Limits and behavior

| Topic | Behavior |
|---|---|
| **Authentication** | OAuth2 with Client ID and Client Secret. The access token lasts 1 hour and is renewed automatically; if the API rejects it, the server logs in again once. |
| **Rate limit** | Action1 doesn't publish a number. On `429` the server waits for the `Retry-After` delay and retries. Local throttling can be turned on with `ACTION1_RATE_LIMIT`. |
| **Permissions** | Each route needs a permission from the credential's role. Without it, the response is `{"erro": "sem_permissao", ...}` with the name of the missing permission. |
| **Organizations** | A single-organization account is used automatically. With several, endpoints, CVEs, patches and software queries cover all of them (`orgId=all`); the other tools ask for `org_id` (or `ACTION1_ORG_ID`). |
| **Pagination** | `from` + `limit`, with `next_page` or `total_items` (sometimes an estimate such as `"10+"`). The server never requests 1-item pages, because `limit=1` misbehaves in the API. |
| **Dates** | The API answers in UTC, formatted `YYYY-MM-DD_HH-mm-ss`. In the tools, `YYYY-MM-DD` dates are read as days in Brasília time. |
| **Errors** | `401`, `403`, `404`, `400` (with the API's message) and timeouts come back as JSON: `{"erro": ..., "mensagem": ...}`. Timeouts and `5xx` errors are retried with backoff. |
| **Large responses** | Responses longer than `ACTION1_MAX_CHARS` are truncated (long strings such as base64 images and scripts first, then lists), with a hint to narrow the query. Use `arquivo_saida` to save the complete result. |

<details>
<summary><b>Optional environment variables</b></summary>

| Variable | Default | Purpose |
|---|---|---|
| `ACTION1_REGION` | auto-detected | `na`, `na-2`, `eu`, `uk` or `au` |
| `ACTION1_BASE_URL` | | Explicit base URL (overrides the region) |
| `ACTION1_ORG_ID` | the only organization | Organization used in place of `{orgId}` |
| `ACTION1_RATE_LIMIT` | `0` | Requests per minute (`0` disables local throttling) |
| `ACTION1_PAGE_SIZE` | `100` | Page size for automatic pagination |
| `ACTION1_MAX_RETRIES` | `3` | Retries on `429`, `5xx` and timeouts |
| `ACTION1_MAX_ESPERA` | `120` | Longest wait (seconds) accepted for a `429` retry |
| `ACTION1_TIMEOUT` | `60` | Per-request timeout (seconds) |
| `ACTION1_MAX_CHARS` | `60000` | Maximum response size before truncation |
| `ACTION1_LOG_LEVEL` | `WARNING` | Log level (always written to stderr) |

</details>

## 🔒 Security

- **Read-only.** The server only sends `GET` requests; the one exception is the internal `POST /oauth2/token` login. Three `GET` routes are also blocked, even with `permitir_nao_listados=True`: the agent installer link, the Deployer installer link and remote sessions.
- **Use a Viewer credential.** The server's blocklist is a second layer; the role on the credential is the first. A Viewer key can't change anything even if a request gets through.
- **Secret handling.** The Client ID and Secret are read only from the environment, never written to logs, and the secret and tokens are removed from every response and error message.
- **Audited.** Every API call, including `GET`s, shows up in Action1's Audit Trail under the credential's user.
- **Real company data.** The credential sees your whole fleet, so conversations may contain hostnames, IP and MAC addresses, logged-on user names and vulnerability details. Request only what you need and follow your company's data protection policy.
- **One credential per person.** Never share the secret in chat, e-mail or GitHub issues. If it leaks, revoke it in **Settings → API Credentials** right away.

## 📥 Other installation methods

Requires Python 3.10 or newer.

| Method | Command |
|---|---|
| PyPI | `pip install action1-mcp-server` |
| uv, without installing | `uvx action1-mcp-server` (in `claude_desktop_config.json`: `"command": "uvx", "args": ["action1-mcp-server"]`) |
| GitHub | `pip install git+https://github.com/jpedrocrc/Action1-MCP-Server` |

<details>
<summary><b>Windows: "command not found"</b></summary>

`pip` installs the executable in `...\Python3xx\Scripts`. If that folder is not on your `PATH`, your AI client cannot find `action1-mcp-server`. Use the full path to the `.exe` in `"command"`, or set `"command": "python"` and `"args": ["-m", "action1_mcp"]`.

</details>

## 🛠 Development

<details>
<summary><b>Project structure</b></summary>

| File | Contents |
|---|---|
| `pyproject.toml` | Package metadata, dependencies and the `action1-mcp-server` command |
| `src/action1_mcp/server.py` | MCP server and tools |
| `src/action1_mcp/ENDPOINTS.md` | API map. The server reads the JSON block at the end of this file, so supporting a new route only takes adding it there. |
| `test_server.py` | Offline tests and coverage tests against the real API |

</details>

**Local setup**

```bash
git clone https://github.com/jpedrocrc/Action1-MCP-Server
cd Action1-MCP-Server
pip install -e .
```

With `-e`, code changes take effect without reinstalling; just restart your AI client. To switch back to the published version, run `pip uninstall -y action1-mcp-server`, then `pip install action1-mcp-server`.

> [!NOTE]
> The package requires `mcp<2`. Version 2.x of the `mcp` SDK renamed `FastMCP`, and the server has not been migrated yet.

**Tests**

```bash
python test_server.py --offline
```

Runs without network access. It checks the API map, tool registration, pagination (against simulated responses) and the safeguards (blocked routes, `GET`-only code, secret and token masking).

```bash
python test_server.py
```

Needs `ACTION1_CLIENT_ID` and `ACTION1_CLIENT_SECRET`. It calls every mapped route with `limit=2`, reuses the IDs it finds to test routes that need one, then calls every tool. Routes the credential's role can't reach are reported as `SEM PERMISSÃO`, not as failures. It takes about 1 minute.

To try the server in the MCP Inspector (requires `uv` and `npx`), run the command below and set `ACTION1_CLIENT_ID` and `ACTION1_CLIENT_SECRET` under *Environment Variables* before connecting:

```bash
mcp dev src/action1_mcp/server.py
```

<details>
<summary><b>Releasing a new version</b></summary>

1. Bump the version in `pyproject.toml` (`version`) and `src/action1_mcp/__init__.py` (`__version__`). PyPI never accepts the same version number twice.
2. Run both test modes.
3. Build:
   ```powershell
   Remove-Item -Recurse -Force dist -ErrorAction SilentlyContinue; uv build
   ```
4. Publish with a PyPI token scoped to the `action1-mcp-server` project:
   ```powershell
   $env:UV_PUBLISH_TOKEN = "pypi-..."; uv publish
   ```
5. Check in a clean environment: `pip install --upgrade action1-mcp-server`, then `pip show action1-mcp-server`.
6. Commit and push to GitHub.

If a published version is broken, **yank** it on PyPI (project → Releases → version → *Yank*) and publish the fix as a new version. Don't delete files: deletion is permanent and the file name can never be reused.

</details>

## 📋 Changelog

| Version | Changes |
|---|---|
| **1.0.0** | First release. |

## 📄 License

[MIT](LICENSE) © João Pedro Rodrigues
