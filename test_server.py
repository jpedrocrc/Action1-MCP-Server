"""Confere a cobertura do servidor contra a API real do Action1.

Uso:
    python test_server.py             # chama cada rota mapeada (limit=2) e cada ferramenta
    python test_server.py --offline   # só valida mapeamento, ferramentas e travas (sem rede)

O modo online precisa de ACTION1_CLIENT_ID e ACTION1_CLIENT_SECRET no ambiente.
Rotas que a credencial não pode ler (403) aparecem como SEM PERMISSÃO, não como falha:
com uma chave de perfil viewer isso é o esperado para licença, papéis, logs e deployers.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path
from typing import Any

try:
    from action1_mcp import server
except ImportError:  # rodando do repositório sem `pip install .`
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
    from action1_mcp import server

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

OK, FALHA, PULADO, SEM_PERMISSAO = "OK", "FALHA", "PULADO", "SEM PERMISSÃO"


def _resumo(r: dict[str, Any]) -> str:
    if "erro" in r:
        return f"{r['erro']} ({r.get('status_http', '-')}): {r['mensagem'][:170]}"
    dados = r.get("dados")
    if isinstance(dados, list):
        return f"{len(dados)} registro(s)" + (" (há mais)" if r.get("tem_mais") else "")
    if isinstance(dados, dict):
        if "content_type" in dados:
            return f"arquivo {dados.get('content_type')}"
        if isinstance(dados.get("items"), list):
            return f"{len(dados['items'])} item(ns), total_items={dados.get('total_items', '-')}"
        return f"objeto ({len(dados)} campos)"
    return type(dados).__name__


def _itens(r: dict[str, Any]) -> list[dict[str, Any]]:
    dados = r.get("dados")
    if isinstance(dados, dict):
        dados = dados.get("items")
    return [x for x in dados or [] if isinstance(x, dict)] if isinstance(dados, list) else []


def _extrair(rota: str, r: dict[str, Any], ids: dict[str, dict[str, str]]) -> None:
    """Guarda os ids que as rotas dependentes precisam (namespace = rota de origem)."""
    itens = _itens(r)
    if not itens:
        return
    p = itens[0]
    simples = {
        "users": "userId", "roles": "roleId", "audit/events": "id", "endpoints/managed/{orgId}": "endpointId",
        "endpoints/groups/{orgId}": "groupId", "endpoints/deployers/{orgId}": "deployerId",
        "automations/action-templates": "templateId", "automations/schedules/{orgId}": "automationId",
        "automations/instances/{orgId}": "instanceId", "scripts/all": "scriptId",
        "data-sources/all": "dataSourceId", "settings/all": "settingId", "setting-templates/all": "templateId",
    }
    if rota in simples:
        ids.setdefault(rota, {})[simples[rota]] = p.get("id")
        if rota == "endpoints/managed/{orgId}":
            ids[rota]["_nome"] = p.get("name")
    elif rota == "vulnerabilities/{orgId}":
        ids[rota] = {"cveId": p.get("cve_id")}
    elif rota in ("updates/{orgId}", "software-repository/{orgId}"):
        com_versao = next((x for x in itens if x.get("versions")), p)
        versao = (com_versao.get("versions") or [{}])[0]
        ids[rota] = {"packageId": com_versao.get("id"), "versionId": versao.get("id")}
    elif rota == "reports/all":
        relatorios = [x for x in itens if x.get("type") == "Report"]
        # Installed Software tem linhas com drill-down (testa drilldown e export de linha).
        preferido = next((x for x in relatorios if x["id"].startswith("installed_software")), relatorios[0] if relatorios else p)
        ids[rota] = {"reportOrCategoryId": preferido["id"], "reportId": preferido["id"]}
    elif rota == "reportdata/{orgId}/{reportId}/data":
        linha = next((x for x in itens if x.get("drilldown")), p)
        ids[rota] = {"reportId": ids["reports/all"]["reportId"], "reportRowId": linha.get("id")}
    elif rota == "automations/instances/{orgId}/{instanceId}/endpoint-results":
        ids.setdefault("automations/instances/{orgId}", {})["endpointId"] = p.get("id")


async def online() -> int:
    if not (os.environ.get("ACTION1_CLIENT_ID") and os.environ.get("ACTION1_CLIENT_SECRET")):
        print("Defina ACTION1_CLIENT_ID e ACTION1_CLIENT_SECRET para o teste online (ou use --offline).")
        return 2

    resultados: list[tuple[str, str, str]] = []

    def registrar(rotulo: str, r: dict[str, Any]) -> None:
        if r.get("erro") == "sem_permissao":
            status = SEM_PERMISSAO
        else:
            status = FALHA if "erro" in r else OK
        resultados.append((rotulo, status, _resumo(r)))

    org = await server.resolver_org(None)
    print(f"Organização de teste: {org} | região: {server._token.base_url}\n")
    ids: dict[str, dict[str, str]] = {}

    for rota, info in server.ROTAS.items():
        teste = info.get("teste") or {}
        fonte = teste.get("depende_de")
        valores = {"orgId": org, **ids.get(fonte or "", {})}
        if rota == "automations/instances/{orgId}/{instanceId}/endpoint-results/{endpointId}/details":
            valores = {"orgId": org, **ids.get("automations/instances/{orgId}", {})}
        faltando = [p for p in re.findall(r"\{(\w+)\}", rota) if not valores.get(p)]
        if faltando:
            resultados.append((rota, PULADO, f"sem id para {', '.join(faltando)} (depende de {fonte})"))
            continue
        caminho = server.montar_rota(rota, **{k: v for k, v in valores.items() if v})
        print(f"-> {rota} ...", flush=True)
        r = await server.consultar(caminho, dict(teste.get("params") or {}), limite_chars=10**12)
        registrar(rota, r)
        if "erro" not in r:
            _extrair(rota, r, ids)

    # Ferramentas de alto nível
    maquina = ids.get("endpoints/managed/{orgId}", {}).get("endpointId")
    cve = ids.get("vulnerabilities/{orgId}", {}).get("cveId")
    execucao = ids.get("automations/instances/{orgId}", {}).get("instanceId")
    chamadas = [
        ("tool listar_organizacoes", server.listar_organizacoes()),
        ("tool listar_maquinas", server.listar_maquinas(max_registros=5)),
        ("tool listar_maquinas(reinicio_pendente)", server.listar_maquinas(reinicio_pendente=True, max_registros=5)),
        ("tool listar_vulnerabilidades(critica)", server.listar_vulnerabilidades(severidade="critica", max_registros=5)),
        ("tool listar_vulnerabilidades(kev)", server.listar_vulnerabilidades(apenas_kev=True, max_registros=5)),
        ("tool listar_atualizacoes(critica)", server.listar_atualizacoes(severidade="critica", max_registros=5)),
        ("tool listar_softwares", server.listar_softwares(max_registros=5)),
        ("tool listar_automacoes(agendadas)", server.listar_automacoes(max_registros=5)),
        ("tool listar_automacoes(execucoes)", server.listar_automacoes(tipo="execucoes", max_registros=5)),
        ("tool consultar_relatorio(catálogo)", server.consultar_relatorio()),
        ("tool consultar_relatorio(Reboot Required)", server.consultar_relatorio("Reboot Required", max_registros=5)),
        ("tool listar_auditoria", server.listar_auditoria(max_registros=5)),
        ("tool listar_rotas", server.listar_rotas()),
        ("tool resumo_ambiente", server.resumo_ambiente()),
    ]
    if maquina:
        chamadas.append(("tool buscar_maquina(id)", server.buscar_maquina(maquina, incluir_softwares=True)))
        nome = ids["endpoints/managed/{orgId}"].get("_nome")
        if nome:
            chamadas.append(("tool buscar_maquina(nome)", server.buscar_maquina(nome, incluir_atualizacoes=False,
                                                                            incluir_vulnerabilidades=False)))
        chamadas.append(("tool listar_softwares(maquina)", server.listar_softwares(maquina_id=maquina, max_registros=5)))
    if cve:
        chamadas.append(("tool buscar_cve", server.buscar_cve(cve)))
    chamadas.append(("tool buscar_cve(fora da org)", server.buscar_cve("CVE-2014-0160")))
    if execucao:
        chamadas.append(("tool listar_automacoes(execucao_id)", server.listar_automacoes(execucao_id=execucao, max_registros=5)))
    for rotulo, coro in chamadas:
        print(f"-> {rotulo} ...", flush=True)
        r = await coro
        if "erro" in r:
            registrar(rotulo, r)
        else:
            chaves = [k for k in r if k not in ("rota", "params")][:6]
            resultados.append((rotulo, OK, _resumo(r) if "dados" in r else "chaves: " + ", ".join(chaves)))

    largura = max(len(r[0]) for r in resultados)
    print("\n" + "=" * 110)
    for rotulo, status, obs in resultados:
        print(f"{rotulo:<{largura}}  {status:<14} {obs}")
    print("=" * 110)
    cont = {s: sum(1 for r in resultados if r[1] == s) for s in (OK, FALHA, SEM_PERMISSAO, PULADO)}
    print(f"{len(server.ROTAS)} rotas mapeadas | " + " | ".join(f"{n} {s}" for s, n in cont.items()))
    return 1 if cont[FALHA] else 0


async def offline() -> int:
    falhas = 0

    def conferir(descricao: str, condicao: bool) -> None:
        nonlocal falhas
        print(f"[{'OK' if condicao else 'FALHA'}] {descricao}")
        falhas += 0 if condicao else 1

    conferir(f"ENDPOINTS.md carregado ({len(server.ROTAS)} rotas)", len(server.ROTAS) >= 60)
    ferramentas = {t.name for t in await server.mcp.list_tools()}
    esperadas = {"action1_get", "listar_rotas", "listar_organizacoes", "listar_maquinas", "buscar_maquina",
                 "listar_vulnerabilidades", "buscar_cve", "listar_atualizacoes", "listar_softwares",
                 "listar_automacoes", "consultar_relatorio", "listar_auditoria", "resumo_ambiente"}
    conferir(f"ferramentas registradas: {sorted(ferramentas)}", esperadas <= ferramentas)

    conferir("normaliza URL completa (next_page) com query",
             server.normalizar_endpoint("https://app.action1.com/api/3.0/users?limit=2&from=2")
             == ("users", {"limit": "2", "from": "2"}))
    conferir("resolve template de máquina",
             server.resolver_endpoint("endpoints/managed/abc/def/missing-updates")["path"]
             == "endpoints/managed/{orgId}/{endpointId}/missing-updates")
    conferir("literal vence placeholder (match-conflicts)",
             server.resolver_endpoint("software-repository/abc/match-conflicts")["path"]
             == "software-repository/{orgId}/match-conflicts")
    conferir("monta rota codificando ids com espaço",
             server.montar_rota("reports/all/{reportOrCategoryId}", reportOrCategoryId="a b~c") == "reports/all/a%20b~c")

    for ep in ("oauth2/token", "endpoints/agent-installation/x/WindowsMSI",
               "endpoints/deployer-installation/x/windowsEXE", "endpoints/managed/x/y/remote-sessions/z",
               "installed-software/x/requery", "updates/x/approvals", "automations/instances/x/y/stop",
               "endpoints/managed/x/y/move", "enterprise/request-closure"):
        r = await server.consultar(ep, permitir_nao_listados=True)
        conferir(f"bloqueia: {ep}", r.get("erro") == "bloqueado")
    r = await server.consultar("endpoints/managed/x/{endpointId}")
    conferir("recusa rota com placeholder sem id (sem chamar a API)", r.get("erro") == "rota_incompleta")
    r = await server.consultar("naoexiste")
    conferir("recusa rota não mapeada", r.get("erro") == "rota_nao_mapeada")
    r = await server.consultar("search/x", {})
    conferir("exige query em search (sem chamar a API)", r.get("erro") == "parametro_obrigatorio")
    r = await server.consultar("automations/instances/all", {})
    conferir("recusa automations/instances/all (500 na API)", r.get("erro") == "parametro_invalido")
    conferir("remove credenciais dos params",
             not {"client_secret", "access_token"} & set(server._limpar_params({"client_secret": "x", "access_token": "y", "a": 1})))
    conferir("booleanos viram Yes/No", server._limpar_params({"a": True, "b": False}) == {"a": "Yes", "b": "No"})

    fonte = Path(server.__file__).read_text(encoding="utf-8")
    conferir("único POST é o do token; nenhum PUT/PATCH/DELETE",
             len(re.findall(r"\.post\(", fonte)) == 1 and "/oauth2/token" in fonte
             and not re.search(r"\.(put|patch|delete|request)\(", fonte))

    falso = "segredo-falso-de-teste-123"
    os.environ["ACTION1_CLIENT_SECRET"] = falso
    server._token.access = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0ZSJ9.c2lnbmF0dXJhX2Zha2U"
    texto = server._ocultar(f"secret {falso} | Authorization: Bearer {server._token.access} | "
                            f'{{"refresh_token": "abcdefghijk"}}')
    conferir("oculta secret, token e refresh_token em mensagens",
             falso not in texto and server._token.access not in texto and "abcdefghijk" not in texto)
    server._token.access = ""

    conferir("converte data de Brasília para UTC no formato do Action1",
             server._para_a1("2026-10-01", False) == "2026-10-01_03-00-00"
             and server._para_a1("2026-10-01", True) == "2026-10-02_02-59-59")
    conferir("lê data do Action1", server._parse_a1("2026-10-10_22-35-18").hour == 22)
    conferir("severidade por CVSS", [server._severidade_cvss(s) for s in ("9.8", "7.5", "5", "3.3")]
             == ["Critical", "High", "Medium", "Low"])

    # Paginação com respostas simuladas
    class Resp:
        def __init__(self, corpo):
            self._c = corpo

        def json(self):
            return self._c

    original = server.requisitar
    try:
        dados = list(range(7))

        async def falsa_next_page(ep, params):
            i, n = int(params["from"]), int(params["limit"])
            lote = [{"id": x} for x in dados[i:i + n]]
            return Resp({"items": lote, "total_items": "10+", "next_page": "x" if i + n < len(dados) else ""})

        server.requisitar = falsa_next_page
        itens, paginas, tem_mais, _ = await server._paginar("users", {"limit": "3"}, 100)
        conferir("pagina por next_page (total '10+')", len(itens) == 7 and paginas == 3 and not tem_mais)
        itens, paginas, tem_mais, _ = await server._paginar("users", {"limit": "3"}, 5)
        conferir("respeita max_registros e marca tem_mais", len(itens) == 5 and tem_mais)

        async def falsa_abreviada(ep, params):
            i, n = int(params["from"]), int(params["limit"])
            return Resp({"items": [{"id": x} for x in dados[i:i + n]], "total_items": "7", "from": str(i)})

        server.requisitar = falsa_abreviada
        itens, paginas, tem_mais, _ = await server._paginar("vulnerabilities/x", {"limit": "4"}, 100)
        conferir("pagina por total_items (página abreviada)", len(itens) == 7 and paginas == 2 and not tem_mais)

        async def falsa_ignora_limit(ep, params):
            return Resp({"items": [{"id": x} for x in dados], "total_items": "7", "next_page": "x"})

        server.requisitar = falsa_ignora_limit
        itens, paginas, _, _ = await server._paginar("endpoints/managed/x", {"limit": "2"}, 100)
        conferir("para quando a API ignora o limit", len(itens) == 7 and paginas == 1)
    finally:
        server.requisitar = original

    grande = {"value": "A" * 200000, "itens": list(range(10))}
    cortado, aviso = server._caber(grande, 5000)
    conferir("corta textos longos (base64) antes de cortar listas",
             aviso is not None and len(cortado["itens"]) == 10 and len(cortado["value"]) < 1000)

    print(f"\n{'Tudo certo.' if not falhas else f'{falhas} falha(s).'}")
    return 1 if falhas else 0


if __name__ == "__main__":
    modo = offline if "--offline" in sys.argv else online
    sys.exit(asyncio.run(modo()))
