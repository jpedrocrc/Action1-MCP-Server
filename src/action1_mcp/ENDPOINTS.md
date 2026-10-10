# Mapeamento da API do Action1 (somente leitura)

Base: `https://app.action1.com/api/3.0` (região América do Norte; veja as demais abaixo)
Levantado em 10/10/2026 a partir da especificação OpenAPI 3.1 oficial (versão 3.1.0), publicada em
[app.action1.com/apidocs](https://app.action1.com/apidocs) e linkada em
[action1.com/api-documentation](https://www.action1.com/api-documentation/). Todas as rotas abaixo
foram chamadas contra a API real com uma chave de perfil **viewer**.

> O bloco JSON no final deste arquivo é a fonte de verdade do `server.py`: o servidor
> lê esse bloco na inicialização para validar rotas, saber como paginar e responder
> `listar_rotas()`. Se a API ganhar uma rota nova de leitura, basta acrescentá-la ao JSON.

> **Vocabulário:** no Action1, *endpoint* é a **máquina gerenciada** (computador com o agente).
> Para não confundir com as rotas da API, este servidor chama as rotas de "rotas" e os
> computadores de "máquinas".

---

## 1. Regras gerais

| Item | Valor | Fonte |
|---|---|---|
| Regiões | `app.action1.com` (América do Norte), `app.na-2.action1.com` (América do Norte 2), `app.eu.action1.com` (Europa), `app.uk.action1.com` (Reino Unido), `app.au.action1.com` (Austrália). Sempre com o sufixo `/api/3.0`. A credencial só funciona na região da conta (nas outras: 401 "Incorrect authentication data"). | `servers` da spec; testado |
| Autenticação | `POST /oauth2/token` com JSON `{"client_id", "client_secret"}` → `{access_token, refresh_token, expires_in: 3600, token_type: "Bearer"}`. As demais chamadas usam `Authorization: Bearer <access_token>`. Client ID e Secret são criados no console em **Configurações > API Credentials**. | `OAuth 2.0` da spec |
| Papéis | `enterprise admin`, `organization admin`, `manager`, `viewer`. Cada rota exige uma permissão (`view_endpoints`, `view_vulnerabilities`, ...); sem ela a API devolve 403 com o nome da permissão. | `security` da spec |
| Rate limit | **Não documentado em número.** A spec só descreve o 429 com header `Retry-After` (segundos) e `details.retry_after` no corpo. | componente `429` |
| Erros | JSON `{id: "0", type: "Error", status, developer_message, user_message}`. | componente `Error` |
| Escopo | Quase toda rota tem `{orgId}` no caminho (o `id` de `GET /organizations`). Algumas aceitam `all` para consultar todas as organizações (testado: `endpoints/managed`, `vulnerabilities`, `updates`, `installed-software`). `automations/instances/all` devolve **500**. Rotas de escopo empresa (`scripts`, `settings`, `reports`, `data-sources`) usam o literal `all`. | spec; testado |
| Datas | Respostas em **UTC** no formato `AAAA-MM-DD_HH-mm-ss` (ex.: `2026-10-10_22-35-18`). `audit/events` aceita `timefrom`/`timeto` no mesmo formato. `vulnerabilities` aceita `published_date_start/end` como `AAAA-MM-DD`. | spec; testado |
| Auditoria | Toda chamada à API (inclusive GET) fica registrada no Audit Trail do Action1 com o usuário da chave. | testado |

### 1.1 Paginação (`from` + `limit`)

- Parâmetros: `limit` (tamanho da página; padrão 50) e `from` (índice do primeiro registro, começa em 0).
- A resposta vem em dois formatos:
  - **ResultPage**: `{items[], total_items, limit, next_page, prev_page, self}`. `next_page` é a URL completa da próxima página e fica vazio na última.
  - **ResultPage abreviada** (`vulnerabilities`, `permissions`, `vulnerabilities/.../endpoints`): `{items[], total_items, limit, from}`, sem `next_page`.
- `total_items` é texto e pode vir como estimativa, ex. `"10+"` (`installed-software`, `automations/instances`).
- Relatórios trazem ainda `total_errors`, `total_live_responses`, `total_sent_requests`, `last_requery`.
- **Peculiaridade (testada):** `limit=1` não funciona direito: em `endpoints/managed` devolve **todos** os registros e em `endpoints/groups` devolve **nenhum** na primeira página. O servidor nunca pede página menor que 2.
- `limit=500` funciona (testado em `vulnerabilities` e `audit/events`). A spec não informa o máximo.

### 1.2 Parâmetros comuns de listagem

| Parâmetro | Uso |
|---|---|
| `filter` | Substring, sem diferenciar maiúsculas; o objeto volta se **qualquer** campo contiver o texto. |
| `sortby` | Campo de ordenação; prefixo `-` para decrescente (ex. `-name`). |
| `fields` | Campos extras. Em `endpoints/managed`: `*`, `missing_updates`, `vulnerabilities` (traz contagens e `update_status`/`vulnerability_status`). Em `software-repository` e `updates`: `*`. |
| `reset_cache` | `Yes` força recalcular o cache (endpoints, vulnerabilidades). |

### 1.3 Rotas que existem mas NÃO são expostas

| Rota | Motivo |
|---|---|
| Todo `POST`, `PUT`, `PATCH` e `DELETE` (criar/alterar/excluir máquinas, grupos, scripts, pacotes, automações, usuários, papéis, organizações, remediações, assinaturas, aprovações, re-query de relatórios, upload, mover máquina, parar automação, encerrar conta...) | Escrita. O servidor só faz GET (a única exceção é o `POST /oauth2/token` interno, para obter o token). |
| `GET endpoints/agent-installation/{orgId}/{installType}` | Gera o link de instalação do agente da organização (registra "Download Agent" na auditoria; com ele é possível colocar máquinas na organização). |
| `GET endpoints/deployer-installation/{orgId}/windowsEXE` | Gera o link de instalação do Deployer (mesmo motivo). |
| `GET endpoints/managed/{orgId}/{endpointId}/remote-sessions/{sessionId}` | Sessão de acesso remoto (exige `remote_connect`). Fora do escopo de um servidor de consulta. |
| `oauth2/token` | Autenticação; tratada internamente. |

---

## 2. Rotas de leitura

Legenda da coluna **viewer**: resultado com a chave de teste de perfil viewer em 10/10/2026
(✔ = 200; 403 = sem permissão para esse perfil; — = não testado por falta de dado).

### 2.1 Organizações, empresa e usuários

| Rota | Conteúdo | Parâmetros | Permissão | viewer |
|---|---|---|---|---|
| `organizations` | Organizações da empresa: `id, name, description, enterprise_id` | `admin` (Yes/No) | — | ✔ |
| `enterprise` | Empresa: `id, name, description, verified` | | — | ✔ |
| `me` | Usuário da chave: `id, first_name, last_name, email, user_type (API/Interactive), system_role, mfa, enabled...` | | — | ✔ |
| `users`, `users/{userId}` | Usuários (mesmos campos de `me`) | `filter`, `user_type` (API/Interactive), `from`, `limit` | `view_users` | ✔ |
| `users/{userId}/roles` | Papéis de um usuário | `from`, `limit` | `manage_users` | 403 |
| `roles`, `roles/{roleId}`, `roles/{roleId}/users` | Papéis (RBAC) e seus usuários | `filter`, `sortby`, `fields`, `from`, `limit` | `manage_roles` | 403 |
| `permissions` | Modelos de permissão: `id, name, description, available_scopes` | `filter`, `sortby`, `from`, `limit` | — | ✔ |
| `subscription/enterprise`, `subscription/usage/enterprise` | Licença e uso da empresa | | `manage_enterprise` | 403 |
| `subscription/usage/organizations`, `.../{orgId}` | Uso de licença por organização | | `manage_organizations` | ✔ (lista vazia) |
| `me/report-subscriptions` | Assinaturas de relatório por e-mail do usuário da chave | `from`, `limit` | — | ✔ |
| `audit/events`, `audit/events/{id}` | Trilha de auditoria: `id, event, description, details, object_name, object_url, user_name, user_id, timestamp, org_id, org_name, status_message` | `event` (lista: Login, Remote Connect, Remote Disconnect, Create User, View Report, Download Agent, Search, Export Report, POST, GET, ...), `timefrom`, `timeto` (`AAAA-MM-DD_HH-MM-SS`, UTC), `filter`, `sortby`, `from`, `from_id`, `limit` | `view_audit` | ✔ |
| `audit/export` | Auditoria em CSV | mesmos de `audit/events` + `format` | `view_audit` | ✔ |

### 2.2 Máquinas (endpoints) e grupos

| Rota | Conteúdo | Parâmetros | Permissão | viewer |
|---|---|---|---|---|
| `search/{orgId}` | Busca até 10 objetos (máquinas, pacotes, relatórios) que contenham o texto | `query` (**obrigatório**), `limit` | `view_endpoints`, `view_software_repository`, `view_reports` | ✔ |
| `endpoints/status/{orgId}` | `{endpoints_added: yes/no}` | | — | ✔ |
| `endpoints/managed/{orgId}` | Máquinas gerenciadas (aceita `all`) | `filter`, `sortby`, `fields` (`*`, `missing_updates`, `vulnerabilities`), `status` (Connected, Disconnected, Pending Uninstall), `online_status`, `update_status`, `vulnerability_status` (SUCCESS, WARNING, ERROR), `reboot_required` (Yes/No), `os`, `reset_cache`, `from`, `limit` | `view_endpoints` | ✔ |
| `endpoints/managed/{orgId}/{endpointId}` | Uma máquina | | `view_endpoints` | ✔ |
| `endpoints/managed/{orgId}/{endpointId}/missing-updates` | Atualizações faltando na máquina (mesmo layout de `updates`) | `approval_status` (New, Approved, Declined, -Declined), `security_severity` (Critical, -Critical, Important, Moderate, Low, Unspecified, Other), `filter`, `sortby`, `from`, `limit` | `view_endpoints` | ✔ |
| `endpoints/groups/{orgId}`, `.../{groupId}` | Grupos: `id, name, description, include_filter, exclude_filter, contents` | `filter`, `sortby`, `from`, `limit` | `view_endpoints` | ✔ |
| `endpoints/groups/{orgId}/{groupId}/contents` | Máquinas do grupo (mesmos filtros de `endpoints/managed`) | idem | `view_endpoints` | ✔ |
| `endpoints/agent-deployment/{orgId}` | Configuração de implantação automática do agente | | `manage_endpoints` | 403 |
| `endpoints/deployers/{orgId}`, `.../{deployerId}` | Serviços Deployer | `status`, `filter`, `sortby`, `os`, `installed_since`, `from`, `limit` | `manage_endpoints` | 403 |
| `logs/{orgId}` | Logs de diagnóstico | `level` (Debug ... Critical), `sortby`, `from`, `limit` | `manage_endpoints` | 403 |

Campos da máquina: `id, name, device_name, status (Connected/Disconnected/Pending Uninstall), online_status, last_seen, address, MAC, OS, platform (Windows/Mac/Linux), architecture, agent_version, agent_install_date, last_boot_time, subscription_status, user, comment, serial, manufacturer, CPU_name, CPU_size, RAM, disk, NIC, video, WiFi, AD_organization_unit, AD_security_groups, reboot_required, organization_id, group_membership[] {id, name}, custom`.
Com `fields=*`: também `missing_updates {critical, other}`, `vulnerabilities {critical, other}`, `update_status`, `vulnerability_status`.

### 2.3 Vulnerabilidades

| Rota | Conteúdo | Parâmetros | Permissão | viewer |
|---|---|---|---|---|
| `vulnerabilities/{orgId}` | CVEs presentes nas máquinas (aceita `all`): `cve_id, cvss_score, endpoints_count, published_date, vector_string, remediation_status, remediation_deadline, cisa_kev (Yes/No), software[] {product_name, platform, endpoints_count, versions[], available_updates[] {version, package_id, version_id}, cve_origin}` | `score` (Critical, High, Medium, Low), `remediation_status` (Overdue, Due_soon, Overdue_due_soon, Due_later, Control_applied, All_except_control_applied), `published_date_start/end` (AAAA-MM-DD), `remediation_required_start_day/end_day` (dias), `endpoint_id`, `CVEIDs` (lista com vírgula), `filter`, `sortby`, `reset_cache`, `from`, `limit` | `view_vulnerabilities` | ✔ |
| `vulnerabilities/{orgId}/{cveId}` | Detalhe do CVE: CVSS, vetor, impactos, descrição. **Devolve 200 mesmo se nenhuma máquina tiver o CVE** (confira em `.../endpoints`); CVE inexistente dá **500** | | `view_vulnerabilities` | ✔ |
| `vulnerabilities/{orgId}/{cveId}/endpoints` | Máquinas afetadas: `endpoint_id, endpoint_name, OS, user, software[]` | `product_names`, `filter`, `sortby`, `from`, `limit` | `view_vulnerabilities` | ✔ |
| `vulnerabilities/{orgId}/{cveId}/remediations` | Controles compensatórios registrados | `filter`, `sortby`, `from`, `limit` | `view_vulnerabilities` | ✔ |
| `CVE-descriptions/{cveId}` | Detalhe do CVE fora do contexto de organização | | `view_vulnerabilities` | ✔ |

### 2.4 Atualizações (patches), softwares instalados e repositório

| Rota | Conteúdo | Parâmetros | Permissão | viewer |
|---|---|---|---|---|
| `updates/{orgId}` | Atualizações faltando (aceita `all`): pacote (`id, name, vendor, update_type, kb_number, reboot_needed, size, optional, update_source, recommended`) + `versions[] {id, version, security_severity, approval_status, release_date, update_sla_deadline, update_sla_status, scoped_approvals}` | `approval_status`, `security_severity`, `custom`, `builtin`, `only_latest` (padrão Yes), `update_sla_start_day/end_day`, `fields`, `filter`, `sortby`, `from`, `limit` | `approve_updates`, `view_dashboards` ou `manage_automations` | ✔ |
| `updates/{orgId}/{packageId}` | Atualizações de um pacote | mesmos | idem | ✔ |
| `updates/{orgId}/{packageId}/versions/{versionId}/endpoints` | Máquinas que precisam dessa versão | `filter`, `sortby`, `from`, `limit` | idem | ✔ |
| `installed-software/{orgId}/data` | Inventário de softwares (aceita `all`); linhas de relatório: `fields {Name, Version, Vendor, Install Type, Platform, Endpoints, Update Status}` | `live_only`, `filter`, `sortby`, `from`, `limit` | `view_installed_software` | ✔ |
| `installed-software/{orgId}/data/{endpointId}` | Softwares de uma máquina: `fields {Name, Version, Vendor, Install Date, Install Location, Installed For, Install Type, Update Status}` | `filter`, `sortby`, `from`, `limit` | `view_installed_software` ou `view_endpoints` | ✔ |
| `installed-software/{orgId}/errors` | Erros de coleta do inventário | `filter`, `sortby`, `from`, `limit` | `view_installed_software` | ✔ |
| `software-repository/{orgId}` | Pacotes do repositório (escopo empresa) | `filter`, `builtin`, `custom`, `match_name`, `match_version`, `platform`, `fields`, `sortby`, `from`, `limit` | `view_software_repository` | ✔ |
| `software-repository/{orgId}/{packageId}` | Um pacote; `fields=*` traz `versions` | `fields` | `view_software_repository` | ✔ |
| `software-repository/{orgId}/{packageId}/versions/{versionId}` | Uma versão do pacote | | `view_software_repository` | ✔ |
| `software-repository/{orgId}/match-conflicts`, `.../{packageId}/match-conflicts` | Conflitos de `app_name_match` (regex) com o inventário | `app_name_match` (**obrigatório**; sem ele: 400) | `view_software_repository` | ✔ |

### 2.5 Automações

| Rota | Conteúdo | Parâmetros | Permissão | viewer |
|---|---|---|---|---|
| `automations/schedules/{orgId}` | Automações agendadas: `id, name, settings (ex. "ENABLED WEEKLY:Sun,Fri AT:13-00-00"), settings_timezone, endpoints[], actions[], last_run, next_run, retry_minutes` | `filter`, `sortby`, `from`, `limit` | `view_automations` | ✔ |
| `automations/schedules/{orgId}/{automationId}` | Uma automação agendada | | `view_automations` | ✔ |
| `automations/schedules/{orgId}/{automationId}/deployment-statuses` | Por pacote: `success_rate, deployment_count, failure_count, first_deployed_datetime` | | `view_automations` | ✔ |
| `automations/instances/{orgId}` | Execuções: `id, name, start_time, status (Pending, Stopped, Running, Success, Warning, Error), percent_completed, endpoints[], schedule` (**`all` dá 500**) | `status`, `completed` (yes/no), `endpoint_id`, `filter`, `sortby`, `from`, `limit` | `view_automations` | ✔ |
| `automations/instances/{orgId}/{instanceId}` | Uma execução | | `view_automations` | ✔ |
| `automations/instances/{orgId}/{instanceId}/endpoint-results` | Resultado por máquina: `endpoint_name, time, status, percent_completed, action_name, description` | `last_status`, `filter`, `sortby`, `from`, `limit` | `view_automations` | ✔ |
| `automations/instances/{orgId}/{instanceId}/endpoint-results/{endpointId}/details` | Detalhe (saída) da execução numa máquina | | `view_automations` | ✔ |
| `automations/action-templates`, `.../{templateId}` | Tipos de ação (deploy, script, reboot, ...) | `applicable_to` | — | ✔ |

### 2.6 Relatórios, scripts e configurações

| Rota | Conteúdo | Parâmetros | Permissão | viewer |
|---|---|---|---|---|
| `reports/all` | Categorias e relatórios (`subtree=Yes` traz a árvore toda: ~76 relatórios) | `subtree` | — | ✔ |
| `reports/all/{reportOrCategoryId}` | Um relatório ou categoria | | — | ✔ |
| `reportdata/{orgId}/{reportId}/data` | Linhas do relatório: `id, fields {...}, drilldown` | `live_only`, `details` (só relatórios Summary), `endpoint_id`, `filter`, `sortby`, `from`, `limit` | `view_reports` | ✔ |
| `reportdata/{orgId}/{reportId}/data/{reportRowId}/drilldown` | Detalhe de uma linha (só linhas que trazem `drilldown`; ex. relatório Installed Software). Em linha sem detalhe, o export dá 400 "Items was not found" | `live_only`, `filter`, `sortby`, `from`, `limit` | `view_reports` | ✔ |
| `reportdata/{orgId}/{reportId}/errors` | Erros de coleta do relatório | `filter`, `sortby`, `from`, `limit` | `view_reports` | ✔ |
| `reportdata/{orgId}/{reportId}/export`, `.../data/{reportRowId}/export` | Relatório em CSV ou HTML | `format` (csv, html), `live_only`, `filter`, `sortby`, `from`, `limit` | `view_reports` | ✔ |
| `scripts/all`, `scripts/all/{scriptId}` | Biblioteca de scripts: `id, name, description, platform, language, builtin, status, script_text` | `builtin`, `platform` | `use_scripts` | ✔ |
| `data-sources/all`, `.../{dataSourceId}` | Fontes de dados dos relatórios | `builtin` | `manage_data_sources` ou `manage_reports` | 403 |
| `settings/all`, `settings/all/{settingId}` | Configurações avançadas aplicadas (algumas trazem imagens em base64) | `category` (remote_desktop, custom_branding, sla, sso, software_repository), `filter`, `sortby`, `from`, `limit` | `manage_advanced_settings` | ✔ |
| `setting-templates/all`, `.../{templateId}` | Modelos de configuração | `filter` | — | ✔ |

IDs de relatórios úteis (embutidos): `managed_endpoints_1635942317188` (Managed Endpoints), `missing_third_party___windows_updates_1671801861492`, `missing_critical_updates_1635418508078`, `reboot_required_1635422625514`, `installed_updates_1635420078206`, `windows_update_status`, `antivirus_status_1647107026187`, `os_information_1635436732671`, `all_critical_vulnerabilities`, `known_exploited_vulnerabilities`, `vulnerability_summary`, `installed_software_1635264799139`, `windows_11_hardware_compatibility_1746808184875`. A lista completa vem de `reports/all?subtree=Yes`.

---

## 3. Mapeamento usado pelo código

<!-- ENDPOINTS-JSON:INICIO -->
```json
{
  "base_url": "https://app.action1.com/api/3.0",
  "regioes": {
    "na": "https://app.action1.com/api/3.0",
    "na-2": "https://app.na-2.action1.com/api/3.0",
    "eu": "https://app.eu.action1.com/api/3.0",
    "uk": "https://app.uk.action1.com/api/3.0",
    "au": "https://app.au.action1.com/api/3.0"
  },
  "limites": {
    "rate_limit": "não documentado; a API responde 429 com header Retry-After (segundos)",
    "token": "access_token Bearer válido por 3600 s (renovado automaticamente)",
    "paginacao": "from (índice inicial, 0) + limit (padrão 50). Resposta: items, total_items (texto, pode ser '10+'), next_page (vazio na última) ou from",
    "limit_1": "limit=1 é instável (endpoints/managed devolve tudo; endpoints/groups devolve nada); use 2 ou mais",
    "datas": "respostas em UTC, formato AAAA-MM-DD_HH-mm-ss",
    "auditoria": "toda chamada, inclusive GET, aparece no Audit Trail do Action1"
  },
  "dicas": [
    "No Action1 'endpoint' = máquina gerenciada. orgId vem de GET organizations; muitas rotas aceitam 'all'.",
    "Use {orgId} no caminho para o servidor trocar pela organização padrão (ACTION1_ORG_ID ou a única da conta).",
    "filter é substring em qualquer campo (não é OData). sortby=-campo ordena decrescente.",
    "endpoints/managed com fields=* traz missing_updates, vulnerabilities, update_status e vulnerability_status.",
    "vulnerabilities: score=Critical|High|Medium|Low, remediation_status=Overdue|Due_soon|..., CVEIDs=CVE-1,CVE-2, endpoint_id=<id da máquina>.",
    "updates: security_severity=Critical (ou -Critical para não críticas), approval_status=New|Approved|Declined.",
    "audit/events: timefrom/timeto no formato AAAA-MM-DD_HH-MM-SS (UTC)."
  ],
  "bloqueados": [
    "oauth2/token",
    "endpoints/agent-installation/{orgId}/{installType}",
    "endpoints/deployer-installation/{orgId}/windowsEXE",
    "endpoints/managed/{orgId}/{endpointId}/remote-sessions/{sessionId}"
  ],
  "endpoints": [
    {
      "path": "organizations",
      "descricao": "Organizações da empresa (id, name, description).",
      "permissao": null,
      "paginacao": "from_limit",
      "parametros": {"admin": "Yes = só organizações em que o usuário é admin", "from": "", "limit": ""},
      "campos": ["id", "type", "name", "description", "enterprise_id"],
      "teste": {"params": {}}
    },
    {
      "path": "enterprise",
      "descricao": "Dados da empresa (enterprise).",
      "permissao": null,
      "paginacao": "nenhuma",
      "parametros": {},
      "campos": ["id", "name", "description", "allowed_fast_closure", "verified"],
      "teste": {"params": {}}
    },
    {
      "path": "me",
      "descricao": "Usuário dono da chave de API.",
      "permissao": null,
      "paginacao": "nenhuma",
      "parametros": {},
      "campos": ["id", "first_name", "last_name", "email", "phone", "timezone", "roles", "enabled", "session_timeout", "mfa", "identity_provider", "email_verified", "system", "system_role", "impersonating", "user_type"],
      "teste": {"params": {}}
    },
    {
      "path": "me/report-subscriptions",
      "descricao": "Assinaturas de relatório por e-mail do usuário da chave.",
      "permissao": null,
      "paginacao": "from_limit",
      "parametros": {"from": "", "limit": ""},
      "campos": [],
      "teste": {"params": {}}
    },
    {
      "path": "users",
      "descricao": "Usuários da empresa.",
      "permissao": "view_users",
      "paginacao": "from_limit",
      "parametros": {"filter": "Substring em qualquer campo", "user_type": "API ou Interactive", "from": "", "limit": ""},
      "campos": ["id", "first_name", "last_name", "email", "phone", "timezone", "roles", "enabled", "mfa", "identity_provider", "email_verified", "system_role", "user_type"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "users/{userId}",
      "descricao": "Um usuário.",
      "permissao": "view_users",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "users"}
    },
    {
      "path": "users/{userId}/roles",
      "descricao": "Papéis atribuídos a um usuário.",
      "permissao": "manage_users",
      "paginacao": "from_limit",
      "parametros": {"from": "", "limit": ""},
      "teste": {"depende_de": "users"}
    },
    {
      "path": "roles",
      "descricao": "Papéis (RBAC).",
      "permissao": "manage_roles",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "fields": "* para todos os campos", "from": "", "limit": ""},
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "roles/{roleId}",
      "descricao": "Um papel.",
      "permissao": "manage_roles",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "roles"}
    },
    {
      "path": "roles/{roleId}/users",
      "descricao": "Usuários de um papel.",
      "permissao": "view_users + (assign_roles ou manage_roles)",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "roles"}
    },
    {
      "path": "permissions",
      "descricao": "Modelos de permissão (id, name, description, available_scopes).",
      "permissao": null,
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["id", "name", "description", "available_scopes"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "subscription/enterprise",
      "descricao": "Licença da empresa.",
      "permissao": "manage_enterprise",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"params": {}}
    },
    {
      "path": "subscription/usage/enterprise",
      "descricao": "Uso de licença da empresa.",
      "permissao": "manage_enterprise",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"params": {}}
    },
    {
      "path": "subscription/usage/organizations",
      "descricao": "Uso de licença por organização.",
      "permissao": "manage_organizations",
      "paginacao": "from_limit",
      "parametros": {},
      "teste": {"params": {}}
    },
    {
      "path": "subscription/usage/organizations/{orgId}",
      "descricao": "Uso de licença de uma organização.",
      "permissao": "manage_organizations",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"params": {}}
    },
    {
      "path": "audit/events",
      "descricao": "Trilha de auditoria (logins, acesso remoto, mudanças, chamadas de API).",
      "permissao": "view_audit",
      "paginacao": "from_limit",
      "parametros": {"event": "Eventos separados por vírgula: Login, Remote Connect, Remote Disconnect, Create User, View Report, Download Agent, Download Deployer, Search, Export Report, POST, GET...", "timefrom": "AAAA-MM-DD_HH-MM-SS (UTC)", "timeto": "AAAA-MM-DD_HH-MM-SS (UTC)", "filter": "", "sortby": "", "from_id": "Id sequencial do primeiro registro", "from": "", "limit": ""},
      "campos": ["id", "event", "description", "details", "object_name", "object_url", "user_name", "user_id", "timestamp", "org_id", "org_name", "status_message"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "audit/events/{id}",
      "descricao": "Um registro de auditoria.",
      "permissao": "view_audit",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "audit/events"}
    },
    {
      "path": "audit/export",
      "descricao": "Exporta a auditoria em CSV.",
      "permissao": "view_audit",
      "paginacao": "nenhuma",
      "resposta_arquivo": true,
      "parametros": {"event": "", "timefrom": "", "timeto": "", "filter": "", "sortby": "", "from_id": "", "from": "", "limit": "", "format": "csv"},
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "search/{orgId}",
      "descricao": "Busca até 10 objetos (máquinas, pacotes, relatórios) que contenham o texto.",
      "permissao": "view_endpoints, view_software_repository, view_reports",
      "paginacao": "nenhuma",
      "obrigatorios": ["query"],
      "parametros": {"query": "OBRIGATÓRIO: texto a buscar", "limit": "Máximo de itens"},
      "teste": {"params": {"query": "win", "limit": 2}}
    },
    {
      "path": "endpoints/status/{orgId}",
      "descricao": "Se a organização já tem máquinas (endpoints_added yes/no).",
      "permissao": null,
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"params": {}}
    },
    {
      "path": "endpoints/managed/{orgId}",
      "descricao": "Máquinas gerenciadas. Aceita orgId=all. fields=* traz contagem de atualizações e vulnerabilidades.",
      "permissao": "view_endpoints",
      "paginacao": "from_limit",
      "aceita_all": true,
      "parametros": {"filter": "Substring em qualquer campo (nome, IP, usuário...)", "sortby": "Ex.: name, -last_seen", "fields": "*, missing_updates ou vulnerabilities", "status": "Connected, Disconnected, Pending Uninstall", "online_status": "SUCCESS, WARNING, ERROR", "update_status": "SUCCESS, WARNING, ERROR", "vulnerability_status": "SUCCESS, WARNING, ERROR", "reboot_required": "Yes ou No", "os": "Filtro de sistema operacional", "reset_cache": "Yes para recalcular", "from": "", "limit": ""},
      "campos": ["id", "name", "device_name", "status", "online_status", "last_seen", "address", "MAC", "OS", "platform", "architecture", "agent_version", "agent_install_date", "last_boot_time", "subscription_status", "user", "comment", "serial", "manufacturer", "CPU_name", "CPU_size", "RAM", "disk", "NIC", "video", "WiFi", "AD_organization_unit", "AD_security_groups", "reboot_required", "organization_id", "group_membership", "custom", "missing_updates (fields)", "vulnerabilities (fields)", "update_status (fields)", "vulnerability_status (fields)"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "endpoints/managed/{orgId}/{endpointId}",
      "descricao": "Uma máquina gerenciada.",
      "permissao": "view_endpoints",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "endpoints/managed/{orgId}"}
    },
    {
      "path": "endpoints/managed/{orgId}/{endpointId}/missing-updates",
      "descricao": "Atualizações que faltam numa máquina.",
      "permissao": "view_endpoints",
      "paginacao": "from_limit",
      "parametros": {"approval_status": "New, Approved, Declined, -Declined", "security_severity": "Critical, -Critical, Important, Moderate, Low, Unspecified, Other", "filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "endpoints/managed/{orgId}", "params": {"limit": 2}}
    },
    {
      "path": "endpoints/groups/{orgId}",
      "descricao": "Grupos de máquinas.",
      "permissao": "view_endpoints",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["id", "name", "description", "include_filter", "exclude_filter", "contents"],
      "teste": {"params": {}}
    },
    {
      "path": "endpoints/groups/{orgId}/{groupId}",
      "descricao": "Um grupo de máquinas.",
      "permissao": "view_endpoints",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "endpoints/groups/{orgId}"}
    },
    {
      "path": "endpoints/groups/{orgId}/{groupId}/contents",
      "descricao": "Máquinas de um grupo (aceita os filtros de endpoints/managed).",
      "permissao": "view_endpoints",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "fields": "", "status": "", "online_status": "", "update_status": "", "vulnerability_status": "", "reboot_required": "", "os": "", "from": "", "limit": ""},
      "teste": {"depende_de": "endpoints/groups/{orgId}", "params": {"limit": 2}}
    },
    {
      "path": "endpoints/agent-deployment/{orgId}",
      "descricao": "Configuração de implantação automática do agente (não aceita all).",
      "permissao": "manage_endpoints",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"params": {}}
    },
    {
      "path": "endpoints/deployers/{orgId}",
      "descricao": "Serviços Action1 Deployer.",
      "permissao": "manage_endpoints",
      "paginacao": "from_limit",
      "parametros": {"status": "Connected ou Disconnected", "filter": "", "sortby": "", "os": "", "installed_since": "", "from": "", "limit": ""},
      "teste": {"params": {}}
    },
    {
      "path": "endpoints/deployers/{orgId}/{deployerId}",
      "descricao": "Um Deployer.",
      "permissao": "manage_endpoints",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "endpoints/deployers/{orgId}"}
    },
    {
      "path": "logs/{orgId}",
      "descricao": "Logs de diagnóstico.",
      "permissao": "manage_endpoints",
      "paginacao": "from_limit",
      "parametros": {"level": "Debug, Normal, Internal, Important, Error, Critical (nível mínimo)", "sortby": "", "from": "", "limit": ""},
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "vulnerabilities/{orgId}",
      "descricao": "CVEs presentes nas máquinas, com software afetado, atualização disponível, prazo e status de remediação. Aceita orgId=all.",
      "permissao": "view_vulnerabilities",
      "paginacao": "from_limit",
      "aceita_all": true,
      "parametros": {"score": "Critical, High, Medium, Low", "remediation_status": "Overdue, Due_soon, Overdue_due_soon, Due_later, Control_applied, All_except_control_applied", "published_date_start": "AAAA-MM-DD", "published_date_end": "AAAA-MM-DD", "remediation_required_start_day": "Prazo mínimo em dias", "remediation_required_end_day": "Prazo máximo em dias", "endpoint_id": "Id da máquina", "CVEIDs": "CVE-2024-1,CVE-2024-2", "filter": "", "sortby": "", "reset_cache": "", "from": "", "limit": ""},
      "campos": ["cve_id", "cvss_score", "endpoints_count", "published_date", "vector_string", "remediation_status", "remediation_deadline", "cisa_kev", "organization_id", "software{product_name,platform,endpoints_count,versions,available_updates{version,package_id,version_id},cve_origin}"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "vulnerabilities/{orgId}/{cveId}",
      "descricao": "Detalhe de um CVE na organização (CVSS, vetor, impactos, descrição).",
      "permissao": "view_vulnerabilities",
      "paginacao": "nenhuma",
      "parametros": {},
      "campos": ["cve_id", "published_date", "base_severity", "cvss_score", "description", "availability_impact", "confidentiality_impact", "integrity_impact", "vector_string", "version", "exploitability_score", "impact_score"],
      "teste": {"depende_de": "vulnerabilities/{orgId}"}
    },
    {
      "path": "vulnerabilities/{orgId}/{cveId}/endpoints",
      "descricao": "Máquinas afetadas por um CVE.",
      "permissao": "view_vulnerabilities",
      "paginacao": "from_limit",
      "parametros": {"product_names": "Nomes de produto", "filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["endpoint_id", "endpoint_name", "OS", "user", "organization_id", "software"],
      "teste": {"depende_de": "vulnerabilities/{orgId}"}
    },
    {
      "path": "vulnerabilities/{orgId}/{cveId}/remediations",
      "descricao": "Controles compensatórios registrados para um CVE.",
      "permissao": "view_vulnerabilities",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "vulnerabilities/{orgId}"}
    },
    {
      "path": "CVE-descriptions/{cveId}",
      "descricao": "Detalhe de um CVE fora do contexto de organização.",
      "permissao": "view_vulnerabilities",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "vulnerabilities/{orgId}"}
    },
    {
      "path": "updates/{orgId}",
      "descricao": "Atualizações (patches) faltando nas máquinas. Aceita orgId=all.",
      "permissao": "approve_updates, view_dashboards ou manage_automations",
      "paginacao": "from_limit",
      "aceita_all": true,
      "parametros": {"approval_status": "New, Approved, Declined, -Declined", "security_severity": "Critical, -Critical, Important, Moderate, Low, Unspecified, Other", "custom": "Yes/No", "builtin": "Yes/No", "only_latest": "Yes (padrão) exclui as substituídas", "update_sla_start_day": "", "update_sla_end_day": "", "fields": "*", "filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["id", "name", "vendor", "description", "update_type", "kb_number", "reboot_needed", "size", "optional", "update_source", "recommended", "organization_ids", "versions{id,version,security_severity,approval_status,release_date,update_sla_deadline,update_sla_status,scoped_approvals}"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "updates/{orgId}/{packageId}",
      "descricao": "Atualizações de um pacote.",
      "permissao": "approve_updates, view_dashboards ou manage_automations",
      "paginacao": "from_limit",
      "parametros": {"approval_status": "", "security_severity": "", "only_latest": "", "fields": "", "filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "updates/{orgId}"}
    },
    {
      "path": "updates/{orgId}/{packageId}/versions/{versionId}/endpoints",
      "descricao": "Máquinas que precisam de uma versão de atualização.",
      "permissao": "approve_updates, view_dashboards ou manage_automations",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "updates/{orgId}"}
    },
    {
      "path": "installed-software/{orgId}/data",
      "descricao": "Inventário de softwares instalados (linhas de relatório com 'fields'). Aceita orgId=all.",
      "permissao": "view_installed_software",
      "paginacao": "from_limit",
      "aceita_all": true,
      "parametros": {"live_only": "Yes/No", "filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["id", "fields{Name,Version,Vendor,Install Type,Platform,Endpoints,Update Status,_Missing_Updates}", "drilldown"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "installed-software/{orgId}/data/{endpointId}",
      "descricao": "Softwares instalados numa máquina.",
      "permissao": "view_installed_software ou view_endpoints",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["id", "fields{Name,Version,Vendor,Install Date,Install Location,Installed For,Install Type,Update Status,Platform}", "last_refresh", "response_type"],
      "teste": {"depende_de": "endpoints/managed/{orgId}", "params": {"limit": 2}}
    },
    {
      "path": "installed-software/{orgId}/errors",
      "descricao": "Erros de coleta do inventário de softwares.",
      "permissao": "view_installed_software",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "software-repository/{orgId}",
      "descricao": "Pacotes do repositório de software (escopo empresa).",
      "permissao": "view_software_repository",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "builtin": "Yes/No", "custom": "Yes/No", "match_name": "", "match_version": "", "platform": "Windows, Mac, Linux", "fields": "*", "sortby": "", "from": "", "limit": ""},
      "teste": {"params": {"limit": 2, "fields": "*"}}
    },
    {
      "path": "software-repository/{orgId}/match-conflicts",
      "descricao": "Conflitos de app_name_match (regex) antes de criar um pacote.",
      "permissao": "view_software_repository",
      "paginacao": "nenhuma",
      "obrigatorios": ["app_name_match"],
      "parametros": {"app_name_match": "OBRIGATÓRIO: regex do nome do software"},
      "teste": {"params": {"app_name_match": "^7-Zip"}}
    },
    {
      "path": "software-repository/{orgId}/{packageId}",
      "descricao": "Um pacote do repositório; fields=* traz as versões.",
      "permissao": "view_software_repository",
      "paginacao": "nenhuma",
      "parametros": {"fields": "* ou versions"},
      "teste": {"depende_de": "software-repository/{orgId}"}
    },
    {
      "path": "software-repository/{orgId}/{packageId}/match-conflicts",
      "descricao": "Conflitos de app_name_match ao editar um pacote.",
      "permissao": "view_software_repository",
      "paginacao": "nenhuma",
      "obrigatorios": ["app_name_match"],
      "parametros": {"app_name_match": "OBRIGATÓRIO: regex do nome do software"},
      "teste": {"depende_de": "software-repository/{orgId}", "params": {"app_name_match": "^7-Zip"}}
    },
    {
      "path": "software-repository/{orgId}/{packageId}/versions/{versionId}",
      "descricao": "Uma versão de pacote do repositório.",
      "permissao": "view_software_repository",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "software-repository/{orgId}"}
    },
    {
      "path": "automations/action-templates",
      "descricao": "Modelos de ação de automação (deploy, script, reboot...).",
      "permissao": null,
      "paginacao": "nenhuma",
      "parametros": {"applicable_to": "Contexto, ex. /API/installed-software"},
      "teste": {"params": {}}
    },
    {
      "path": "automations/action-templates/{templateId}",
      "descricao": "Um modelo de ação.",
      "permissao": null,
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "automations/action-templates"}
    },
    {
      "path": "automations/schedules/{orgId}",
      "descricao": "Automações agendadas (políticas de patch, scripts recorrentes).",
      "permissao": "view_automations",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["id", "name", "settings", "settings_timezone", "retry_minutes", "endpoints", "actions", "last_run", "next_run", "randomize_start"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "automations/schedules/{orgId}/{automationId}",
      "descricao": "Uma automação agendada.",
      "permissao": "view_automations",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "automations/schedules/{orgId}"}
    },
    {
      "path": "automations/schedules/{orgId}/{automationId}/deployment-statuses",
      "descricao": "Status de implantação por pacote de uma automação.",
      "permissao": "view_automations",
      "paginacao": "from_limit",
      "parametros": {},
      "campos": ["name", "vendor", "version", "package_id", "version_id", "success_rate", "deployment_count", "failure_count", "first_deployed_datetime", "excluded"],
      "teste": {"depende_de": "automations/schedules/{orgId}"}
    },
    {
      "path": "automations/instances/{orgId}",
      "descricao": "Execuções de automações (em andamento e concluídas). orgId=all dá erro 500.",
      "permissao": "view_automations",
      "paginacao": "from_limit",
      "parametros": {"status": "Pending, Stopped, Running, Success, Warning, Error", "completed": "yes/no", "endpoint_id": "Id da máquina", "filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["id", "name", "start_time", "status", "percent_completed", "endpoints", "actions", "schedule", "endpoint_results", "retry_minutes"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "automations/instances/{orgId}/{instanceId}",
      "descricao": "Uma execução de automação.",
      "permissao": "view_automations",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "automations/instances/{orgId}"}
    },
    {
      "path": "automations/instances/{orgId}/{instanceId}/endpoint-results",
      "descricao": "Resultado de uma execução por máquina.",
      "permissao": "view_automations",
      "paginacao": "from_limit",
      "parametros": {"last_status": "", "filter": "", "sortby": "", "from": "", "limit": ""},
      "campos": ["id", "endpoint_name", "time", "status", "percent_completed", "action_name", "description", "details"],
      "teste": {"depende_de": "automations/instances/{orgId}", "params": {"limit": 2}}
    },
    {
      "path": "automations/instances/{orgId}/{instanceId}/endpoint-results/{endpointId}/details",
      "descricao": "Detalhe (saída) da execução numa máquina.",
      "permissao": "view_automations",
      "paginacao": "from_limit",
      "parametros": {},
      "teste": {"depende_de": "automations/instances/{orgId}"}
    },
    {
      "path": "reports/all",
      "descricao": "Categorias e relatórios. subtree=Yes traz a árvore inteira.",
      "permissao": null,
      "paginacao": "nenhuma",
      "parametros": {"subtree": "Yes para a árvore toda"},
      "campos": ["id", "type (Report/ReportCategory)", "name", "description", "report_data", "parent_category", "simple", "builtin", "data_sources"],
      "teste": {"params": {"subtree": "Yes"}}
    },
    {
      "path": "reports/all/{reportOrCategoryId}",
      "descricao": "Um relatório ou categoria.",
      "permissao": null,
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "reports/all"}
    },
    {
      "path": "reportdata/{orgId}/{reportId}/data",
      "descricao": "Linhas de um relatório (ids em reports/all?subtree=Yes).",
      "permissao": "view_reports",
      "paginacao": "from_limit",
      "parametros": {"live_only": "Yes/No", "details": "yes (só relatórios Summary)", "endpoint_id": "", "filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "reports/all", "params": {"limit": 2}}
    },
    {
      "path": "reportdata/{orgId}/{reportId}/data/{reportRowId}/drilldown",
      "descricao": "Detalhe de uma linha de relatório.",
      "permissao": "view_reports",
      "paginacao": "from_limit",
      "parametros": {"live_only": "", "filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "reportdata/{orgId}/{reportId}/data"}
    },
    {
      "path": "reportdata/{orgId}/{reportId}/errors",
      "descricao": "Erros de coleta de um relatório.",
      "permissao": "view_reports",
      "paginacao": "from_limit",
      "parametros": {"filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "reports/all", "params": {"limit": 2}}
    },
    {
      "path": "reportdata/{orgId}/{reportId}/export",
      "descricao": "Exporta um relatório em CSV ou HTML.",
      "permissao": "view_reports",
      "paginacao": "nenhuma",
      "resposta_arquivo": true,
      "parametros": {"format": "csv (padrão) ou html", "live_only": "", "filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"depende_de": "reports/all", "params": {"limit": 2}}
    },
    {
      "path": "reportdata/{orgId}/{reportId}/data/{reportRowId}/export",
      "descricao": "Exporta o detalhe de uma linha de relatório.",
      "permissao": "view_reports",
      "paginacao": "nenhuma",
      "resposta_arquivo": true,
      "parametros": {"format": "csv ou html"},
      "teste": {"depende_de": "reportdata/{orgId}/{reportId}/data"}
    },
    {
      "path": "scripts/all",
      "descricao": "Biblioteca de scripts (com o texto do script).",
      "permissao": "use_scripts",
      "paginacao": "from_limit",
      "parametros": {"builtin": "Yes/No", "platform": "Windows, Mac, Linux", "from": "", "limit": ""},
      "campos": ["id", "name", "description", "platform", "language", "builtin", "status", "script_text"],
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "scripts/all/{scriptId}",
      "descricao": "Um script.",
      "permissao": "use_scripts",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "scripts/all"}
    },
    {
      "path": "data-sources/all",
      "descricao": "Fontes de dados dos relatórios.",
      "permissao": "manage_data_sources ou manage_reports",
      "paginacao": "from_limit",
      "parametros": {"builtin": "Yes/No"},
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "data-sources/all/{dataSourceId}",
      "descricao": "Uma fonte de dados.",
      "permissao": "manage_data_sources ou manage_reports",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "data-sources/all"}
    },
    {
      "path": "settings/all",
      "descricao": "Configurações avançadas aplicadas (algumas trazem imagens em base64).",
      "permissao": "manage_advanced_settings",
      "paginacao": "from_limit",
      "parametros": {"category": "remote_desktop, custom_branding, sla, sso, software_repository", "filter": "", "sortby": "", "from": "", "limit": ""},
      "teste": {"params": {"limit": 2}}
    },
    {
      "path": "settings/all/{settingId}",
      "descricao": "Uma configuração avançada.",
      "permissao": "manage_advanced_settings",
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "settings/all"}
    },
    {
      "path": "setting-templates/all",
      "descricao": "Modelos de configuração avançada.",
      "permissao": null,
      "paginacao": "from_limit",
      "parametros": {"filter": ""},
      "teste": {"params": {}}
    },
    {
      "path": "setting-templates/all/{templateId}",
      "descricao": "Um modelo de configuração.",
      "permissao": null,
      "paginacao": "nenhuma",
      "parametros": {},
      "teste": {"depende_de": "setting-templates/all"}
    }
  ]
}
```
<!-- ENDPOINTS-JSON:FIM -->
