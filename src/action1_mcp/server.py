"""MCP server (stdio) somente leitura para a API do Action1.

O mapeamento de rotas vem do bloco JSON em ENDPOINTS.md (fonte de verdade).
Client ID e Secret são lidos de ACTION1_CLIENT_ID / ACTION1_CLIENT_SECRET; o secret
e os tokens nunca são logados nem devolvidos nas respostas. O servidor só faz GET
(a única exceção é o POST interno em /oauth2/token para obter o token).

No Action1, "endpoint" é a máquina gerenciada. Para não confundir com as rotas da
API, aqui as rotas se chamam "rotas" e os computadores, "máquinas".
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import sys
import time
from collections import Counter, deque
from datetime import date, datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote

import httpx
from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

AQUI = Path(__file__).resolve().parent
ENDPOINTS_MD = AQUI / "ENDPOINTS.md"


def _env_int(nome: str, padrao: int) -> int:
    try:
        return int(os.environ.get(nome, padrao))
    except ValueError:
        return padrao


TIMEOUT_S = _env_int("ACTION1_TIMEOUT", 60)
PAGE_SIZE = max(2, _env_int("ACTION1_PAGE_SIZE", 100))  # limit=1 é instável na API
RATE_LIMIT = _env_int("ACTION1_RATE_LIMIT", 0)  # req/min; 0 desliga o limitador local
MAX_TENTATIVAS = _env_int("ACTION1_MAX_RETRIES", 3)
MAX_ESPERA_S = _env_int("ACTION1_MAX_ESPERA", 120)  # maior espera aceita num único retry
MAX_CHARS = _env_int("ACTION1_MAX_CHARS", 60000)  # acima disso a resposta é cortada
BRASILIA = timezone(timedelta(hours=-3))  # sem horário de verão desde 2019

# stdout é o canal do protocolo MCP: log só em stderr. httpx loga as URLs em INFO.
logging.basicConfig(level=os.environ.get("ACTION1_LOG_LEVEL", "WARNING"), stream=sys.stderr)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
log = logging.getLogger("action1-mcp")


def _credenciais() -> tuple[str, str]:
    cid = os.environ.get("ACTION1_CLIENT_ID", "").strip()
    secret = os.environ.get("ACTION1_CLIENT_SECRET", "").strip()
    if not cid or not secret:
        raise Action1Erro(
            "configuracao",
            "Defina ACTION1_CLIENT_ID e ACTION1_CLIENT_SECRET. Crie a credencial no console do "
            "Action1 em Configurações > API Credentials (de preferência com o papel Viewer).",
        )
    return cid, secret


_JWT_RE = re.compile(r"eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}")


def _ocultar(texto: str) -> str:
    """Remove o client secret e os tokens de qualquer texto que possa sair do servidor."""
    segredos = [os.environ.get("ACTION1_CLIENT_SECRET", "").strip(), _token.access, _token.refresh]
    for s in segredos:
        if s and len(s) >= 8:
            texto = texto.replace(s, "***")
    texto = _JWT_RE.sub("***", texto)
    texto = re.sub(r"(?i)(bearer\s+)[^\s\"']+", r"\1***", texto)
    return re.sub(r"(?i)(\"?(?:client_secret|access_token|refresh_token)\"?\s*[:=]\s*\"?)[^\s\"'&,}]+", r"\1***", texto)


# ---------------------------------------------------------------------------
# Mapeamento (ENDPOINTS.md)
# ---------------------------------------------------------------------------


def carregar_mapeamento(caminho: Path = ENDPOINTS_MD) -> dict[str, Any]:
    texto = caminho.read_text(encoding="utf-8")
    m = re.search(
        r"<!-- ENDPOINTS-JSON:INICIO -->\s*```json\s*(.*?)```\s*<!-- ENDPOINTS-JSON:FIM -->",
        texto,
        re.S,
    )
    if not m:
        raise RuntimeError(f"Bloco ENDPOINTS-JSON não encontrado em {caminho}")
    return json.loads(m.group(1))


MAPA = carregar_mapeamento()
ROTAS: dict[str, dict[str, Any]] = {e["path"]: e for e in MAPA["endpoints"]}
REGIOES: dict[str, str] = MAPA["regioes"]


def _template_regex(path: str) -> re.Pattern[str]:
    partes = [r"[^/]+" if re.fullmatch(r"\{\w+\}", p) else re.escape(p) for p in path.split("/")]
    return re.compile("^" + "/".join(partes) + "$", re.I)


def _ordem(path: str) -> tuple[int, int]:
    # Literais antes de placeholders: "software-repository/{orgId}/match-conflicts"
    # precisa vencer "software-repository/{orgId}/{packageId}".
    return (path.count("{"), -len(path))


_TEMPLATES = [(e["path"], _template_regex(e["path"])) for e in sorted(MAPA["endpoints"], key=lambda e: _ordem(e["path"]))]
_BLOQUEADOS = [_template_regex(b) for b in MAPA.get("bloqueados", [])]
# Defesa extra: trechos de caminho que só existem em operações de escrita ou sensíveis.
_ESCRITA_RE = re.compile(
    r"(?i)(^|/)(oauth2|agent-installation|deployer-installation|remote-sessions|requery|approvals|"
    r"upload|clone|move|stop|trial|quote|request-closure|revoke-closure|additional-actions)(/|$)"
)


def normalizar_endpoint(endpoint: str) -> tuple[str, dict[str, str]]:
    """Aceita 'endpoints/managed/x', '/endpoints/...', '/api/3.0/...', URL completa (next_page) e query string."""
    ep = endpoint.strip()
    extras: dict[str, str] = {}
    if "?" in ep:
        ep, qs = ep.split("?", 1)
        extras = dict(parse_qsl(qs, keep_blank_values=True))
    ep = re.sub(r"^https?://[^/]+", "", ep)
    ep = re.sub(r"^/?(api/3\.0|API)/", "", ep.lstrip("/"))
    return ep.strip("/"), extras


def resolver_endpoint(ep: str) -> dict[str, Any] | None:
    for path, rx in _TEMPLATES:
        if rx.match(ep):
            return ROTAS[path]
    return None


def checar_bloqueio(ep: str) -> None:
    if any(rx.match(ep) for rx in _BLOQUEADOS) or _ESCRITA_RE.search(ep):
        raise Action1Erro(
            "bloqueado",
            f"A rota '{ep}' altera dados, gera instaladores ou abre acesso remoto no Action1 "
            "e não é permitida neste servidor somente leitura.",
        )


def montar_rota(template: str, **ids: str) -> str:
    """Preenche um template do mapeamento, codificando cada id como segmento de caminho."""
    def trocar(m: re.Match[str]) -> str:
        valor = str(ids[m.group(1)])
        return quote(valor, safe="%:@!$&'()*+,;=-._~")
    return re.sub(r"\{(\w+)\}", trocar, template)


# ---------------------------------------------------------------------------
# Cliente HTTP: token OAuth2, rate limit, retry e tratamento de erros
# ---------------------------------------------------------------------------


class Action1Erro(Exception):
    def __init__(self, tipo: str, mensagem: str, status: int | None = None, detalhe: Any = None):
        super().__init__(mensagem)
        self.tipo = tipo
        self.mensagem = mensagem
        self.status = status
        self.detalhe = detalhe

    def como_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"erro": self.tipo, "mensagem": _ocultar(self.mensagem)}
        if self.status is not None:
            d["status_http"] = self.status
        if self.detalhe is not None:
            d["detalhe"] = json.loads(_ocultar(json.dumps(self.detalhe, ensure_ascii=False, default=str)))
        return d


class LimitadorTaxa:
    """Janela deslizante de 60 s. A API não documenta limite; por padrão fica desligado."""

    def __init__(self, por_minuto: int):
        self.por_minuto = por_minuto
        self.chamadas: deque[float] = deque()
        self.lock = asyncio.Lock()

    async def aguardar(self) -> None:
        if self.por_minuto <= 0:
            return
        async with self.lock:
            while True:
                agora = time.monotonic()
                while self.chamadas and agora - self.chamadas[0] >= 60:
                    self.chamadas.popleft()
                if len(self.chamadas) < self.por_minuto:
                    self.chamadas.append(agora)
                    return
                espera = 60 - (agora - self.chamadas[0]) + 0.05
                log.info("Rate limit local: aguardando %.1fs", espera)
                await asyncio.sleep(espera)


class _Token:
    """access_token em memória, renovado antes de expirar (expires_in = 3600 s)."""

    def __init__(self) -> None:
        self.access = ""
        self.refresh = ""
        self.expira = 0.0
        self.base_url: str | None = None
        self.lock = asyncio.Lock()

    def invalidar(self) -> None:
        self.access, self.expira = "", 0.0


_token = _Token()
_limitador = LimitadorTaxa(RATE_LIMIT)
_cliente: httpx.AsyncClient | None = None


def _http() -> httpx.AsyncClient:
    global _cliente
    if _cliente is None:
        _cliente = httpx.AsyncClient(
            timeout=httpx.Timeout(TIMEOUT_S, connect=15),
            headers={"Accept": "application/json", "User-Agent": "action1-mcp/1.0"},
            follow_redirects=True,
        )
    return _cliente


def _bases_candidatas() -> list[str]:
    explicita = os.environ.get("ACTION1_BASE_URL", "").strip().rstrip("/")
    if explicita:
        return [explicita if explicita.endswith("/api/3.0") else explicita + "/api/3.0"]
    regiao = os.environ.get("ACTION1_REGION", "").strip().lower()
    if regiao:
        if regiao not in REGIOES:
            raise Action1Erro("configuracao", f"ACTION1_REGION inválida: '{regiao}'. Use uma de: {', '.join(REGIOES)}.")
        return [REGIOES[regiao]]
    return list(REGIOES.values())  # sem região: descobre na primeira autenticação


async def _obter_token() -> tuple[str, str]:
    """Devolve (base_url, access_token), autenticando se preciso."""
    async with _token.lock:
        if _token.access and time.time() < _token.expira and _token.base_url:
            return _token.base_url, _token.access
        cid, secret = _credenciais()
        bases = [_token.base_url] if _token.base_url else _bases_candidatas()
        ultima = ""
        for base in bases:
            try:
                resp = await _http().post(f"{base}/oauth2/token", json={"client_id": cid, "client_secret": secret})
            except httpx.HTTPError as e:
                ultima = f"Falha de conexão com {base}: {type(e).__name__}"
                continue
            if resp.status_code == 200:
                corpo = resp.json()
                _token.access = corpo["access_token"]
                _token.refresh = corpo.get("refresh_token", "")
                _token.expira = time.time() + float(corpo.get("expires_in", 3600)) - 120
                _token.base_url = base
                return base, _token.access
            corpo = _corpo(resp)
            ultima = _mensagem_api(corpo) or f"HTTP {resp.status_code}"
            if resp.status_code == 429:
                raise Action1Erro("limite_excedido", f"Limite da API excedido ao autenticar: {ultima}", 429)
        raise Action1Erro(
            "nao_autorizado",
            f"Não foi possível autenticar no Action1 ({ultima}). Confira ACTION1_CLIENT_ID e "
            "ACTION1_CLIENT_SECRET (a credencial pode ter sido revogada) e a região "
            f"(tentadas: {', '.join(bases)}).",
            401,
        )


def _retry_after(resp: httpx.Response, corpo: Any, tentativa: int) -> float:
    valor = resp.headers.get("retry-after")
    if valor:
        try:
            return max(float(valor), 1.0)
        except ValueError:
            try:
                alvo = parsedate_to_datetime(valor)
                return max((alvo - datetime.now(alvo.tzinfo)).total_seconds(), 1.0)
            except (TypeError, ValueError):
                pass
    if isinstance(corpo, dict):
        detalhes = corpo.get("details")
        if isinstance(detalhes, dict) and str(detalhes.get("retry_after", "")).isdigit():
            return max(float(detalhes["retry_after"]), 1.0)
    return [30, 60, 120][min(tentativa, 2)]


def _corpo(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except ValueError:
        return resp.text[:2000] or None


def _mensagem_api(corpo: Any) -> str:
    if isinstance(corpo, dict):
        return str(corpo.get("user_message") or corpo.get("developer_message") or "")
    return ""


def _limpar_params(params: dict[str, Any] | None) -> dict[str, str]:
    limpos: dict[str, str] = {}
    for k, v in (params or {}).items():
        if v is None or k.lower() in ("client_secret", "client_id", "access_token", "refresh_token"):
            continue  # credenciais vêm só do ambiente
        if isinstance(v, bool):
            v = "Yes" if v else "No"
        elif isinstance(v, (list, tuple)):
            v = ",".join(str(x) for x in v)
        limpos[str(k)] = str(v)
    return limpos


async def requisitar(ep: str, params: dict[str, str]) -> httpx.Response:
    """GET com token, rate limit local, retry em 429/5xx/timeout e erros traduzidos."""
    ultima_falha = ""
    reautenticou = False
    tentativa = 0
    while tentativa <= MAX_TENTATIVAS:
        base, token = await _obter_token()
        await _limitador.aguardar()
        try:
            resp = await _http().get(f"{base}/{ep}", params=params, headers={"Authorization": f"Bearer {token}"})
        except httpx.TimeoutException:
            ultima_falha = f"Timeout após {TIMEOUT_S}s"
        except httpx.HTTPError as e:
            ultima_falha = f"Falha de conexão: {type(e).__name__}"
        else:
            if resp.status_code < 400:
                return resp
            corpo = _corpo(resp)
            msg = _mensagem_api(corpo)
            if resp.status_code == 401:
                if not reautenticou:  # token expirado ou revogado: autentica de novo uma vez
                    reautenticou = True
                    _token.invalidar()
                    continue
                raise Action1Erro(
                    "nao_autorizado",
                    "A API recusou o token (401). Confira se a credencial não foi revogada.",
                    401, corpo,
                )
            if resp.status_code == 403:
                if isinstance(corpo, str):
                    raise Action1Erro(
                        "rota_inexistente",
                        f"O servidor web do Action1 recusou o caminho '{ep}' (403 sem JSON): a rota "
                        "provavelmente não existe. Confira em listar_rotas().",
                        403,
                    )
                raise Action1Erro(
                    "sem_permissao",
                    f"A credencial não tem permissão para '{ep}' (403): {msg}",
                    403, corpo,
                )
            if resp.status_code == 404:
                raise Action1Erro("nao_encontrado", f"Recurso não encontrado em '{ep}' (404). {msg}".strip(), 404, corpo)
            if resp.status_code == 429:
                espera = _retry_after(resp, corpo, tentativa)
                if tentativa >= MAX_TENTATIVAS or espera > MAX_ESPERA_S:
                    raise Action1Erro(
                        "limite_excedido",
                        f"Limite da API excedido (429). Tente de novo em ~{int(espera)}s.",
                        429, {"retry_after_s": int(espera), "resposta": corpo},
                    )
                log.warning("429 recebido; aguardando %.0fs (tentativa %d)", espera, tentativa + 1)
                await asyncio.sleep(espera)
                tentativa += 1
                continue
            if resp.status_code >= 500:
                ultima_falha = f"Erro do servidor Action1 ({resp.status_code}): {msg}".strip(": ")
            else:
                raise Action1Erro(
                    "requisicao_invalida",
                    f"A API recusou a consulta ({resp.status_code}): {msg or 'veja detalhe'}. "
                    "Confira os parâmetros em listar_rotas().",
                    resp.status_code, corpo,
                )
        if tentativa < MAX_TENTATIVAS:
            espera = 2 ** tentativa
            log.warning("%s; nova tentativa em %ds", ultima_falha, espera)
            await asyncio.sleep(espera)
        tentativa += 1
    raise Action1Erro("falha_api", f"{ultima_falha} (após {MAX_TENTATIVAS + 1} tentativas).")


def _decodificar(resp: httpx.Response) -> Any:
    tipo = resp.headers.get("content-type", "")
    if "json" in tipo or resp.content[:1] in (b"{", b"["):
        try:
            return resp.json()
        except ValueError:
            pass
    nome = _nome_arquivo(resp)
    if tipo.startswith("text/") or "csv" in tipo:
        return {"content_type": tipo, "nome_arquivo": nome, "texto": resp.text, "_bytes": resp.content}
    conteudo = resp.content
    d: dict[str, Any] = {
        "content_type": tipo or "application/octet-stream",
        "tamanho_bytes": len(conteudo),
        "nome_arquivo": nome,
    }
    if len(conteudo) <= 512 * 1024:
        d["base64"] = base64.b64encode(conteudo).decode()
    else:
        d["aviso"] = "Arquivo grande demais para devolver inline; use arquivo_saida para salvá-lo."
    d["_bytes"] = conteudo
    return d


def _nome_arquivo(resp: httpx.Response) -> str | None:
    cd = resp.headers.get("content-disposition", "")
    m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", cd)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Organização padrão
# ---------------------------------------------------------------------------

_orgs_cache: list[dict[str, Any]] | None = None


async def _organizacoes() -> list[dict[str, Any]]:
    global _orgs_cache
    if _orgs_cache is None:
        corpo = (await requisitar("organizations", {"limit": "500"})).json()
        itens = corpo.get("items", []) if isinstance(corpo, dict) else []
        _orgs_cache = [{"id": o.get("id"), "name": (o.get("name") or "").strip()} for o in itens]
    return _orgs_cache


async def resolver_org(org_id: str | None, permitir_all: bool = False) -> str:
    """org_id informado > ACTION1_ORG_ID > única organização da conta > 'all' (se a rota aceitar)."""
    if org_id and org_id.strip():
        return org_id.strip()
    padrao = os.environ.get("ACTION1_ORG_ID", "").strip()
    if padrao:
        return padrao
    orgs = await _organizacoes()
    if len(orgs) == 1:
        return orgs[0]["id"]
    if permitir_all:
        return "all"
    if not orgs:
        raise Action1Erro("sem_organizacao", "A credencial não enxerga nenhuma organização.")
    raise Action1Erro(
        "org_obrigatoria",
        "A conta tem várias organizações: informe org_id (ou defina ACTION1_ORG_ID).",
        detalhe={"organizacoes": orgs},
    )


# ---------------------------------------------------------------------------
# Paginação (from + limit)
# ---------------------------------------------------------------------------


def _int(valor: Any) -> int | None:
    try:
        return int(str(valor).strip())
    except (TypeError, ValueError):
        return None  # ex.: "10+" (estimativa)


_META_IGNORADA = {"items", "self", "next_page", "prev_page", "id", "type", "limit", "from"}


async def _paginar(ep: str, params: dict[str, str], max_registros: int):
    tamanho = max(2, int(params.pop("limit", PAGE_SIZE) or PAGE_SIZE))
    inicio = int(params.pop("from", 0) or 0)
    itens: list[Any] = []
    paginas = 0
    tem_mais = False
    extra: dict[str, Any] = {}
    while len(itens) < max_registros:
        pedir = max(2, min(tamanho, max_registros - len(itens)))
        corpo = (await requisitar(ep, {**params, "limit": str(pedir), "from": str(inicio)})).json()
        paginas += 1
        if not isinstance(corpo, dict) or not isinstance(corpo.get("items"), list):
            return corpo, paginas, False, {"aviso_paginacao": "Resposta sem 'items'; paginação interrompida."}
        if paginas == 1:
            extra = {f"api_{k}": v for k, v in corpo.items() if k not in _META_IGNORADA}
        lote = corpo["items"]
        itens.extend(lote)
        inicio += len(lote)
        total = _int(corpo.get("total_items"))
        if not lote:
            break
        if "next_page" in corpo:
            tem_mais = bool(corpo.get("next_page"))
        elif total is not None:
            tem_mais = inicio < total
        else:
            tem_mais = len(lote) >= pedir
        if len(lote) > pedir:  # a API ignorou o limit e mandou tudo
            tem_mais = total is not None and inicio < total
            break
        if not tem_mais:
            break
    if len(itens) > max_registros:
        itens = itens[:max_registros]
        tem_mais = True
    return itens, paginas, tem_mais, extra


# ---------------------------------------------------------------------------
# Controle de tamanho da resposta
# ---------------------------------------------------------------------------


def _tamanho(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, default=str))


def _encurtar_textos(obj: Any, maximo: int, cont: list[int]) -> Any:
    """Corta strings muito longas (imagens base64, scripts, HTML) dentro da estrutura."""
    if isinstance(obj, str) and len(obj) > maximo:
        cont[0] += 1
        return obj[:300] + f"... [cortado: {len(obj):,} caracteres]"
    if isinstance(obj, list):
        return [_encurtar_textos(v, maximo, cont) for v in obj]
    if isinstance(obj, dict):
        return {k: _encurtar_textos(v, maximo, cont) for k, v in obj.items()}
    return obj


def _caber(dados: Any, limite: int) -> tuple[Any, str | None]:
    """Corta a resposta para caber em `limite` caracteres. Devolve (dados, aviso)."""
    total = _tamanho(dados)
    if total <= limite:
        return dados, None
    avisos = []
    cont = [0]
    dados = _encurtar_textos(dados, 3000, cont)
    if cont[0]:
        avisos.append(f"{cont[0]} texto(s) longo(s) (base64, scripts, HTML) foram cortados")
        if _tamanho(dados) <= limite:
            return dados, f"Resposta muito grande ({total:,} caracteres): " + "; ".join(avisos) + "."
    if isinstance(dados, list):
        lo, hi = 0, len(dados)  # busca binária do maior prefixo que cabe
        while lo < hi:
            meio = (lo + hi + 1) // 2
            if _tamanho(dados[:meio]) <= limite:
                lo = meio
            else:
                hi = meio - 1
        avisos.append(f"mostrando só os primeiros {lo} de {len(dados)} registros")
        return dados[:lo], f"Resposta muito grande ({total:,} caracteres): " + "; ".join(avisos) + "."
    if isinstance(dados, dict):
        dados = dict(dados)
        originais: dict[str, int] = {}
        for _ in range(50):
            listas = [(k, v) for k, v in dados.items() if isinstance(v, list) and v]
            if not listas or _tamanho(dados) <= limite:
                break
            k, v = max(listas, key=lambda kv: _tamanho(kv[1]))
            originais.setdefault(k, len(v))
            dados[k] = v[: len(v) // 2]
        if originais:
            dados["_listas_truncadas"] = {k: f"{len(dados[k])} de {n}" for k, n in originais.items()}
            avisos.append("listas internas foram encurtadas (veja _listas_truncadas)")
        if _tamanho(dados) <= limite:
            return dados, f"Resposta muito grande ({total:,} caracteres): " + "; ".join(avisos) + "."
    texto = json.dumps(dados, ensure_ascii=False, default=str)
    return {"json_truncado": texto[:limite]}, f"Resposta muito grande ({total:,} caracteres): JSON cortado."


SUGESTAO_TAMANHO = (
    "Para reduzir: use filter (substring) ou os filtros próprios da rota, um max_registros "
    "menor, ou arquivo_saida para gravar o resultado completo em disco."
)


def _salvar(caminho: str, dados: Any) -> str:
    destino = Path(caminho).expanduser()
    if not destino.is_absolute():
        destino = Path.cwd() / destino  # nunca dentro do pacote instalado
    destino.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(dados, dict) and "_bytes" in dados:
        destino.write_bytes(dados["_bytes"])
    else:
        destino.write_text(json.dumps(dados, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    return str(destino)


# ---------------------------------------------------------------------------
# Núcleo da ferramenta genérica
# ---------------------------------------------------------------------------


async def consultar(
    endpoint: str,
    params: dict[str, Any] | None = None,
    paginar: bool = False,
    max_registros: int = 1000,
    permitir_nao_listados: bool = False,
    arquivo_saida: str | None = None,
    limite_chars: int | None = None,
    org_id: str | None = None,
) -> dict[str, Any]:
    """Executa a consulta e devolve um dict pronto para o MCP (nunca lança exceção)."""
    try:
        if "{orgId}" in endpoint:
            info_previa = resolver_endpoint(normalizar_endpoint(endpoint.replace("{orgId}", "x"))[0])
            org = await resolver_org(org_id, permitir_all=bool(info_previa and info_previa.get("aceita_all")))
            endpoint = endpoint.replace("{orgId}", quote(org, safe=""))
        ep, extras = normalizar_endpoint(endpoint)
        if not ep:
            raise Action1Erro("endpoint_invalido", "Informe uma rota, ex.: 'endpoints/managed/{orgId}'.")
        if re.search(r"\{\w+\}", ep):
            raise Action1Erro(
                "rota_incompleta",
                f"A rota '{ep}' ainda tem placeholders: troque cada {{...}} pelo id correspondente "
                "(só {orgId} é preenchido automaticamente).",
            )
        checar_bloqueio(ep)
        q = _limpar_params({**extras, **(params or {})})
        info = resolver_endpoint(ep)
        avisos: list[str] = []

        if info is None:
            if not permitir_nao_listados:
                raise Action1Erro(
                    "rota_nao_mapeada",
                    f"'{ep}' não está em ENDPOINTS.md. Use listar_rotas() para ver as disponíveis "
                    "ou passe permitir_nao_listados=True para tentar mesmo assim (só GET).",
                    detalhe={"disponiveis": sorted(ROTAS)},
                )
            avisos.append("Rota fora do mapeamento: chamada sem validação de parâmetros.")
        else:
            _validar(ep, info, q)

        if q.get("limit") == "1":
            q["limit"] = "2"  # limit=1 é instável na API (ver ENDPOINTS.md)
        paginada = info is not None and info.get("paginacao") == "from_limit"
        if paginar and paginada:
            dados, paginas, tem_mais, extra = await _paginar(ep, q, max(1, max_registros))
        else:
            dados = _decodificar(await requisitar(ep, q))
            paginas, tem_mais, extra = 1, False, {}
            if isinstance(dados, dict) and isinstance(dados.get("items"), list):
                tem_mais = bool(dados.get("next_page")) or (
                    _int(dados.get("total_items")) is not None
                    and _int(dados.get("from") or 0) + len(dados["items"]) < _int(dados.get("total_items"))
                )
                if tem_mais:
                    avisos.append("Há mais registros: use paginar=True (ou from/limit).")

        resultado: dict[str, Any] = {"rota": ep, "params": q, "paginas_lidas": paginas}
        if isinstance(dados, list):
            resultado["total_registros"] = len(dados)
            resultado["tem_mais"] = tem_mais
        elif tem_mais:
            resultado["tem_mais"] = True
        resultado.update({k: v for k, v in extra.items() if v not in (None, "")})

        if arquivo_saida:
            resultado["arquivo_salvo"] = _salvar(arquivo_saida, dados)
            if isinstance(dados, dict) and "_bytes" in dados:
                dados = {k: v for k, v in dados.items() if k not in ("_bytes", "base64", "texto")}
            else:
                amostra = dados[:5] if isinstance(dados, list) else dados
                dados, _ = _caber(amostra, min(limite_chars or MAX_CHARS, 20000))
                avisos.append("Resultado completo gravado em arquivo_salvo; abaixo vai só uma amostra.")
        elif isinstance(dados, dict) and "_bytes" in dados:
            dados = {k: v for k, v in dados.items() if k != "_bytes"}

        dados, aviso = _caber(dados, limite_chars or MAX_CHARS)
        if aviso:
            avisos.append(aviso)
            avisos.append(SUGESTAO_TAMANHO)
        resultado["dados"] = dados
        if avisos:
            resultado["avisos"] = avisos
        return json.loads(_ocultar(json.dumps(resultado, ensure_ascii=False, default=str)))
    except Action1Erro as e:
        return e.como_dict()
    except Exception as e:  # nunca deixa vazar stack trace com token
        log.exception("Erro inesperado")
        return {"erro": "inesperado", "mensagem": _ocultar(f"{type(e).__name__}: {e}")}


def _validar(ep: str, info: dict[str, Any], q: dict[str, str]) -> None:
    """Validações locais que evitam requisições com erro."""
    chaves = {k.lower() for k in q}
    for obrig in info.get("obrigatorios", []):
        if obrig.lower() not in chaves:
            raise Action1Erro(
                "parametro_obrigatorio",
                f"'{ep}' exige o parâmetro '{obrig}'.",
                detalhe={"parametros": info.get("parametros")},
            )
    if ep.startswith("automations/instances/all"):
        raise Action1Erro(
            "parametro_invalido",
            "automations/instances não aceita orgId=all (a API devolve erro 500). Informe uma organização.",
        )


# ---------------------------------------------------------------------------
# Utilidades das ferramentas de alto nível
# ---------------------------------------------------------------------------


def _parse_a1(valor: Any) -> datetime | None:
    """'2026-10-10_22-35-18' (UTC, formato do Action1) -> datetime com fuso UTC."""
    if not isinstance(valor, str):
        return None
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})(?:[_T ](\d{2})[-:](\d{2})[-:](\d{2}))?.*", valor.strip())
    if not m:
        return None
    partes = [int(p) if p else 0 for p in m.groups()]
    try:
        return datetime(*partes, tzinfo=timezone.utc)
    except ValueError:
        return None


def _para_a1(valor: str, fim_do_dia: bool) -> str:
    """'2026-10-01' (dia em Brasília) ou ISO com hora -> 'AAAA-MM-DD_HH-MM-SS' em UTC."""
    valor = valor.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", valor):
        d = date.fromisoformat(valor)
        local = datetime(d.year, d.month, d.day, tzinfo=BRASILIA)
        if fim_do_dia:
            local += timedelta(days=1, seconds=-1)
    else:
        try:
            local = datetime.fromisoformat(valor.replace("Z", "+00:00"))
        except ValueError:
            raise Action1Erro("data_invalida", f"Data inválida: '{valor}'. Use AAAA-MM-DD.") from None
        if local.tzinfo is None:
            local = local.replace(tzinfo=BRASILIA)
    return local.astimezone(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")


def _sim_nao(valor: bool | None) -> str | None:
    return None if valor is None else ("Yes" if valor else "No")


_SEVERIDADE_CVE = {
    "critica": "Critical", "crítica": "Critical", "critical": "Critical",
    "alta": "High", "high": "High", "media": "Medium", "média": "Medium", "medium": "Medium",
    "baixa": "Low", "low": "Low",
}
_SEVERIDADE_UPDATE = {
    "critica": "Critical", "crítica": "Critical", "critical": "Critical",
    "nao_critica": "-Critical", "não_crítica": "-Critical", "-critical": "-Critical",
    "importante": "Important", "important": "Important", "moderada": "Moderate", "moderate": "Moderate",
    "baixa": "Low", "low": "Low", "nao_especificada": "Unspecified", "unspecified": "Unspecified",
    "outra": "Other", "other": "Other",
}


def _mapear(valor: str | None, tabela: dict[str, str], nome: str) -> str | None:
    if not valor:
        return None
    chave = valor.strip().lower().replace(" ", "_")
    if chave in tabela:
        return tabela[chave]
    if valor in tabela.values():
        return valor
    raise Action1Erro("parametro_invalido", f"{nome} inválido: '{valor}'. Use um de: {', '.join(sorted(set(tabela.values())))}.")


def _score(valor: Any) -> float:
    """CVSS como número; a API manda "N/A" quando o CVE ainda não tem nota."""
    try:
        return float(valor)
    except (TypeError, ValueError):
        return -1.0


def _severidade_cvss(score: Any) -> str | None:
    s = _score(score)
    if s < 0:
        return None
    if s >= 9:
        return "Critical"
    if s >= 7:
        return "High"
    if s >= 4:
        return "Medium"
    return "Low" if s > 0 else "None"


CAMPOS_MAQUINA = (
    "id,name,status,online_status,last_seen,address,OS,platform,user,agent_version,"
    "reboot_required,update_status,vulnerability_status,missing_updates,vulnerabilities,"
    "group_membership,organization_id"
)


def _projetar(itens: list[Any], campos: str | None) -> list[Any]:
    if not campos or campos.strip() == "*":
        return itens
    nomes = [c.strip() for c in campos.split(",") if c.strip()]
    saida = []
    for it in itens:
        if not isinstance(it, dict):
            saida.append(it)
            continue
        d = {n: it.get(n) for n in nomes if n in it}
        if "group_membership" in d and isinstance(d["group_membership"], list):
            d["group_membership"] = [g.get("name") for g in d["group_membership"] if isinstance(g, dict)]
        saida.append(d)
    return saida


def _finalizar(resultado: dict[str, Any]) -> dict[str, Any]:
    if "erro" in resultado:
        return resultado
    dados, aviso = _caber(resultado.get("dados"), MAX_CHARS)
    resultado["dados"] = dados
    if aviso:
        resultado.setdefault("avisos", []).extend([aviso, SUGESTAO_TAMANHO])
    return resultado


def _compactar_update(u: dict[str, Any]) -> dict[str, Any]:
    versoes = [
        {k: v.get(k) for k in ("id", "version", "security_severity", "approval_status", "release_date",
                               "update_sla_deadline", "update_sla_status") if k in v}
        for v in u.get("versions") or [] if isinstance(v, dict)
    ]
    base = {k: u.get(k) for k in ("id", "name", "vendor", "kb_number", "update_type", "update_source",
                                  "reboot_needed", "size", "optional", "recommended") if u.get(k) not in (None, "")}
    base["versions"] = versoes
    return base


def _compactar_vuln(v: dict[str, Any]) -> dict[str, Any]:
    softwares = []
    for s in v.get("software") or []:
        softwares.append({
            "product_name": s.get("product_name"),
            "platform": s.get("platform"),
            "endpoints_count": s.get("endpoints_count"),
            "versoes_instaladas": [x.get("version") for x in s.get("versions") or []],
            "atualizacoes_disponiveis": [x.get("version") for x in s.get("available_updates") or []],
        })
    return {
        "cve_id": v.get("cve_id"),
        "cvss_score": v.get("cvss_score"),
        "severidade": _severidade_cvss(v.get("cvss_score")),
        "cisa_kev": v.get("cisa_kev"),
        "endpoints_count": v.get("endpoints_count"),
        "remediation_status": v.get("remediation_status"),
        "remediation_deadline": v.get("remediation_deadline"),
        "published_date": v.get("published_date"),
        "software": softwares,
        **({"organization_id": v["organization_id"]} if v.get("organization_id") else {}),
    }


# ---------------------------------------------------------------------------
# Servidor MCP
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "action1",
    instructions=(
        "Acesso somente leitura à API do Action1 (gestão de patches, vulnerabilidades e inventário). "
        "No Action1 'endpoint' é a máquina gerenciada; aqui as rotas da API se chamam 'rotas'. "
        "Chame listar_rotas() antes de montar consultas genéricas com action1_get. Quase toda rota "
        "tem {orgId}: use listar_organizacoes(); se a conta tiver uma só organização ela é usada "
        "sozinha. Filtros 'filter' são substring (não OData). Datas da API em UTC no formato "
        "AAAA-MM-DD_HH-mm-ss. Nada é criado, alterado ou executado nas máquinas."
    ),
)


@mcp.tool()
async def action1_get(
    endpoint: str,
    params: dict[str, Any] | None = None,
    paginar: bool = False,
    max_registros: int = 1000,
    org_id: str | None = None,
    permitir_nao_listados: bool = False,
    arquivo_saida: str | None = None,
) -> dict[str, Any]:
    """Chama qualquer rota GET da API do Action1, repassando os parâmetros sem restrição.

    Args:
        endpoint: Caminho relativo a /api/3.0. Use "{orgId}" para a organização padrão, ex.:
            "endpoints/managed/{orgId}", "endpoints/managed/{orgId}/<id da máquina>/missing-updates",
            "vulnerabilities/{orgId}", "vulnerabilities/{orgId}/CVE-2024-1234/endpoints",
            "updates/{orgId}", "installed-software/{orgId}/data", "automations/schedules/{orgId}",
            "automations/instances/{orgId}", "reports/all", "reportdata/{orgId}/<reportId>/data",
            "scripts/all", "audit/events", "organizations", "users". URLs completas (next_page) também valem.
        params: Parâmetros de query, repassados como estão: filter, sortby, fields, from, limit,
            status, score, remediation_status, security_severity, approval_status, endpoint_id etc.
            Booleanos viram Yes/No. As credenciais são adicionadas automaticamente.
        paginar: Se True, percorre as páginas (from/limit) até max_registros. Nesse modo, limit
            no params define o tamanho de cada página (padrão ACTION1_PAGE_SIZE).
        max_registros: Teto de registros quando paginar=True.
        org_id: Organização que substitui {orgId} (padrão: ACTION1_ORG_ID ou a única da conta;
            "all" nas rotas que aceitam).
        permitir_nao_listados: Permite rotas fora do ENDPOINTS.md (novidades da API).
            Rotas de escrita, instaladores e acesso remoto continuam bloqueados.
        arquivo_saida: Caminho opcional para gravar o resultado completo (JSON, ou o CSV/HTML das
            rotas de export). A resposta traz só uma amostra.
    """
    return await consultar(endpoint, params, paginar, max_registros, permitir_nao_listados, arquivo_saida, org_id=org_id)


@mcp.tool()
async def listar_rotas(rota: str | None = None, completo: bool = False) -> dict[str, Any]:
    """Mostra o mapeamento da API: rotas, parâmetros, campos, permissões e limites.

    Args:
        rota: Se informada (ex. "vulnerabilities/{orgId}"), devolve todos os detalhes dessa rota.
        completo: Se True, devolve os detalhes de todas as rotas de uma vez.
    """
    if rota:
        ep, _ = normalizar_endpoint(rota)
        info = resolver_endpoint(ep)
        if not info:
            return {"erro": "rota_nao_mapeada", "disponiveis": sorted(ROTAS)}
        return dict(info)
    base: dict[str, Any] = {
        "regioes": MAPA["regioes"],
        "regiao_em_uso": _token.base_url,
        "limites": MAPA["limites"],
        "dicas": MAPA["dicas"],
        "bloqueadas": MAPA["bloqueados"],
    }
    if completo:
        base["rotas"] = MAPA["endpoints"]
    else:
        base["rotas"] = [
            {
                "path": e["path"],
                "descricao": e["descricao"],
                "permissao": e.get("permissao"),
                "paginada": e.get("paginacao") == "from_limit",
                "parametros": sorted(e.get("parametros", {})),
            }
            for e in MAPA["endpoints"]
        ]
        base["dica"] = "Chame listar_rotas(rota='endpoints/managed/{orgId}') para ver campos e parâmetros."
    return base


@mcp.tool()
async def listar_organizacoes() -> dict[str, Any]:
    """Lista as organizações da conta (id e nome). O id é o orgId das demais rotas."""
    r = await consultar("organizations", {}, paginar=True, max_registros=1000)
    if "erro" in r:
        return r
    r["dados"] = [{k: o.get(k) for k in ("id", "name", "description")} for o in r["dados"]]
    r["org_padrao"] = os.environ.get("ACTION1_ORG_ID") or (r["dados"][0]["id"] if len(r["dados"]) == 1 else None)
    return r


@mcp.tool()
async def listar_maquinas(
    org_id: str | None = None,
    busca: str | None = None,
    status: str | None = None,
    reinicio_pendente: bool | None = None,
    status_atualizacao: str | None = None,
    status_vulnerabilidade: str | None = None,
    sistema: str | None = None,
    grupo_id: str | None = None,
    campos: str = CAMPOS_MAQUINA,
    ordenar: str | None = "name",
    max_registros: int = 500,
) -> dict[str, Any]:
    """Lista as máquinas gerenciadas (endpoints do Action1), paginando sozinho.

    Traz as contagens de atualizações faltando e vulnerabilidades por máquina (fields=*).

    Args:
        org_id: Organização (padrão: a configurada/única; "all" para todas).
        busca: Texto procurado em qualquer campo (nome, IP, usuário, SO, serial...).
        status: Connected, Disconnected ou Pending Uninstall.
        reinicio_pendente: True só as que precisam reiniciar; False só as que não precisam.
        status_atualizacao: SUCCESS, WARNING ou ERROR (situação de patches).
        status_vulnerabilidade: SUCCESS, WARNING ou ERROR.
        sistema: Filtro de sistema operacional (ex. "Windows 11").
        grupo_id: Lista só as máquinas de um grupo (ids em action1_get("endpoints/groups/{orgId}")).
        campos: Campos devolvidos, separados por vírgula ("*" = todos, inclusive hardware).
        ordenar: Campo de ordenação; prefixo "-" para decrescente (ex. "-last_seen").
        max_registros: Máximo de máquinas.
    """
    try:
        org = await resolver_org(org_id, permitir_all=not grupo_id)
    except Action1Erro as e:
        return e.como_dict()
    params: dict[str, Any] = {
        "fields": "*",
        "filter": busca,
        "status": status,
        "reboot_required": _sim_nao(reinicio_pendente),
        "update_status": status_atualizacao,
        "vulnerability_status": status_vulnerabilidade,
        "os": sistema,
        "sortby": ordenar,
    }
    rota = montar_rota("endpoints/groups/{orgId}/{groupId}/contents", orgId=org, groupId=grupo_id) if grupo_id \
        else montar_rota("endpoints/managed/{orgId}", orgId=org)
    r = await consultar(rota, params, True, max_registros, limite_chars=10**12)
    if "erro" not in r and isinstance(r.get("dados"), list):
        r["dados"] = _projetar(r["dados"], campos)
    return _finalizar(r)


_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


@mcp.tool()
async def buscar_maquina(
    maquina: str,
    org_id: str | None = None,
    incluir_atualizacoes: bool = True,
    incluir_vulnerabilidades: bool = True,
    incluir_softwares: bool = False,
) -> dict[str, Any]:
    """Busca uma máquina pelo id ou nome, com hardware, atualizações faltando, CVEs e softwares.

    Args:
        maquina: Id da máquina ou nome (exato ou parcial; se o texto bater com várias máquinas,
            devolve os candidatos; se várias tiverem exatamente esse nome, usa a vista por último).
        org_id: Organização (padrão: a configurada/única; "all" procura em todas).
        incluir_atualizacoes: Lista as atualizações que faltam na máquina.
        incluir_vulnerabilidades: Lista os CVEs presentes na máquina.
        incluir_softwares: Lista os softwares instalados (inventário).
    """
    try:
        org = await resolver_org(org_id, permitir_all=True)
    except Action1Erro as e:
        return e.como_dict()
    alvo = maquina.strip()
    if _UUID_RE.fullmatch(alvo):
        # filter não procura no campo id; a rota da máquina aceita fields=* e orgId=all.
        r = await consultar(montar_rota("endpoints/managed/{orgId}/{endpointId}", orgId=org, endpointId=alvo),
                            {"fields": "*"}, limite_chars=10**12)
        if "erro" in r:
            return r
        candidatos = [r["dados"]] if isinstance(r.get("dados"), dict) else []
    else:
        r = await consultar(montar_rota("endpoints/managed/{orgId}", orgId=org), {"fields": "*", "filter": alvo},
                            True, 200, limite_chars=10**12)
        if "erro" in r:
            return r
        candidatos = [m for m in r["dados"] if isinstance(m, dict)]
    exatos = [m for m in candidatos if alvo.lower() in (str(m.get("id", "")).lower(), str(m.get("name", "")).lower(),
                                                      str(m.get("device_name", "")).lower())]
    escolhidos = exatos or candidatos
    if not escolhidos:
        return {"erro": "nao_encontrado", "mensagem": f"Nenhuma máquina corresponde a '{alvo}'."}
    avisos: list[str] = []
    if len(exatos) > 1:
        # Mesmo nome repetido (ex.: agente reinstalado): fica com a vista mais recentemente.
        exatos.sort(key=lambda m: _parse_a1(m.get("last_seen")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        outras = _projetar(exatos[1:], "id,name,status,last_seen,address,user")
        avisos.append(f"Há {len(exatos)} máquinas com esse nome; mostrando a vista mais recentemente. Outras: "
                      + json.dumps(outras, ensure_ascii=False))
        escolhidos = exatos[:1]
    if len(escolhidos) > 1:
        return {
            "erro": "ambiguo",
            "mensagem": f"{len(escolhidos)} máquinas correspondem a '{alvo}'. Repita com o id ou o nome exato.",
            "candidatos": _projetar(escolhidos, "id,name,status,last_seen,address,OS,user,organization_id"),
        }
    m = escolhidos[0]
    org_m = m.get("organization_id") or org
    mid = m["id"]
    resultado: dict[str, Any] = {"maquina": m}
    if incluir_atualizacoes:
        a = await consultar(montar_rota("endpoints/managed/{orgId}/{endpointId}/missing-updates", orgId=org_m, endpointId=mid),
                            {}, True, 500, limite_chars=10**12)
        if "erro" in a:
            resultado["atualizacoes_faltando"] = a
        else:
            resultado["atualizacoes_faltando"] = [_compactar_update(u) for u in a["dados"]]
            if a.get("tem_mais"):
                avisos.append("Atualizações: parou em 500.")
    if incluir_vulnerabilidades:
        v = await consultar(montar_rota("vulnerabilities/{orgId}", orgId=org_m), {"endpoint_id": mid}, True, 1000,
                            limite_chars=10**12)
        if "erro" in v:
            resultado["vulnerabilidades"] = v
        else:
            resultado["vulnerabilidades"] = sorted((_compactar_vuln(x) for x in v["dados"]),
                                                   key=lambda x: -_score(x.get("cvss_score")))
            if v.get("tem_mais"):
                avisos.append("Vulnerabilidades: parou em 1000.")
    if incluir_softwares:
        s = await consultar(montar_rota("installed-software/{orgId}/data/{endpointId}", orgId=org_m, endpointId=mid),
                            {}, True, 2000, limite_chars=10**12)
        if "erro" in s:
            resultado["softwares"] = s
        else:
            resultado["softwares"] = [
                {k: val for k, val in (row.get("fields") or {}).items() if not k.startswith("_") and k != "order_by"}
                for row in s["dados"] if isinstance(row, dict)
            ]
    if avisos:
        resultado["avisos"] = avisos
    dados, aviso = _caber(resultado, MAX_CHARS)
    if aviso and isinstance(dados, dict):
        dados.setdefault("avisos", []).extend([aviso, SUGESTAO_TAMANHO])
    return dados


@mcp.tool()
async def listar_vulnerabilidades(
    org_id: str | None = None,
    severidade: str | None = None,
    status_remediacao: str | None = None,
    cves: str | None = None,
    maquina_id: str | None = None,
    publicado_de: str | None = None,
    publicado_ate: str | None = None,
    busca: str | None = None,
    apenas_kev: bool = False,
    completo: bool = False,
    ordenar: str | None = None,
    max_registros: int = 300,
) -> dict[str, Any]:
    """Lista os CVEs presentes nas máquinas, com software afetado, atualização disponível e prazo.

    Args:
        org_id: Organização (padrão: a configurada/única; "all" para todas).
        severidade: critica, alta, media ou baixa (ou Critical, High, Medium, Low).
        status_remediacao: Overdue (vencido), Due_soon, Overdue_due_soon, Due_later,
            Control_applied, All_except_control_applied.
        cves: Lista de CVEs separados por vírgula (ex. "CVE-2024-1234,CVE-2024-5678").
        maquina_id: Só os CVEs de uma máquina.
        publicado_de: Data mínima de publicação do CVE (AAAA-MM-DD).
        publicado_ate: Data máxima de publicação do CVE (AAAA-MM-DD).
        busca: Texto procurado em qualquer campo (ex. nome do produto).
        apenas_kev: Só CVEs do catálogo CISA KEV (exploração conhecida). Filtro local: percorre
            a lista inteira antes de aplicar max_registros.
        completo: True devolve o objeto bruto da API; False devolve um resumo por CVE.
        ordenar: Campo de ordenação (ex. "-cvss_score").
        max_registros: Máximo de CVEs.
    """
    try:
        org = await resolver_org(org_id, permitir_all=True)
        score = _mapear(severidade, _SEVERIDADE_CVE, "severidade")
    except Action1Erro as e:
        return e.como_dict()
    params = {
        "score": score,
        "remediation_status": status_remediacao,
        "CVEIDs": cves.replace(" ", "") if cves else None,
        "endpoint_id": maquina_id,
        "published_date_start": publicado_de,
        "published_date_end": publicado_ate,
        "filter": busca,
        "sortby": ordenar,
        "limit": 500,
    }
    teto = 20000 if apenas_kev else max_registros
    r = await consultar(montar_rota("vulnerabilities/{orgId}", orgId=org), params, True, teto, limite_chars=10**12)
    if "erro" in r:
        return r
    itens = r["dados"]
    if apenas_kev:
        itens = [v for v in itens if str(v.get("cisa_kev", "")).lower() == "yes"]
        r["tem_mais"] = len(itens) > max_registros
        itens = itens[:max_registros]
        r["filtro_local"] = "cisa_kev == Yes"
    r["dados"] = itens if completo else [_compactar_vuln(v) for v in itens]
    r["total_registros"] = len(r["dados"])
    return _finalizar(r)


@mcp.tool()
async def buscar_cve(
    cve_id: str,
    org_id: str | None = None,
    incluir_maquinas: bool = True,
    incluir_remediacoes: bool = True,
) -> dict[str, Any]:
    """Detalhe de um CVE: CVSS, vetor, impactos, descrição, máquinas afetadas e controles registrados.

    presente_na_organizacao diz se alguma máquina tem o CVE (a API devolve a descrição de
    qualquer CVE conhecido, mesmo ausente da organização).

    Args:
        cve_id: Ex. "CVE-2024-1234".
        org_id: Organização (padrão: a configurada/única).
        incluir_maquinas: Lista as máquinas afetadas.
        incluir_remediacoes: Lista os controles compensatórios registrados.
    """
    cve = cve_id.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        return {"erro": "parametro_invalido", "mensagem": f"CVE inválido: '{cve_id}'. Use o formato CVE-AAAA-NNNN."}
    try:
        org = await resolver_org(org_id)
    except Action1Erro as e:
        return e.como_dict()
    det = await consultar(montar_rota("vulnerabilities/{orgId}/{cveId}", orgId=org, cveId=cve))
    if det.get("erro") == "nao_encontrado":
        geral = await consultar(montar_rota("CVE-descriptions/{cveId}", cveId=cve))
        if "erro" not in geral:
            geral["presente_na_organizacao"] = False
        return geral
    if "erro" in det:
        return det
    resultado: dict[str, Any] = {"cve": det["dados"], "organizacao": org}
    if incluir_maquinas:
        m = await consultar(montar_rota("vulnerabilities/{orgId}/{cveId}/endpoints", orgId=org, cveId=cve), {}, True, 1000)
        resultado["maquinas_afetadas"] = m if "erro" in m else [
            {
                "endpoint_id": x.get("endpoint_id"),
                "endpoint_name": x.get("endpoint_name"),
                "OS": x.get("OS"),
                "user": x.get("user"),
                "software": [
                    {"product_name": s.get("product_name"),
                     "versoes_instaladas": [v.get("version") for v in s.get("versions") or []],
                     "atualizacoes_disponiveis": [v.get("version") for v in s.get("available_updates") or []]}
                    for s in x.get("software") or []
                ],
            }
            for x in m["dados"]
        ]
    if incluir_remediacoes:
        rem = await consultar(montar_rota("vulnerabilities/{orgId}/{cveId}/remediations", orgId=org, cveId=cve), {}, True, 200)
        resultado["remediacoes"] = rem if "erro" in rem else rem["dados"]
    if isinstance(resultado.get("maquinas_afetadas"), list):
        # A API devolve 200 com a descrição mesmo para CVE que não está em nenhuma máquina.
        resultado["presente_na_organizacao"] = bool(resultado["maquinas_afetadas"])
    dados, _ = _caber(resultado, MAX_CHARS)
    return dados


@mcp.tool()
async def listar_atualizacoes(
    org_id: str | None = None,
    severidade: str | None = None,
    status_aprovacao: str | None = None,
    busca: str | None = None,
    apenas_mais_recentes: bool = True,
    completo: bool = False,
    ordenar: str | None = None,
    max_registros: int = 300,
) -> dict[str, Any]:
    """Lista as atualizações (patches de SO e de terceiros) que faltam nas máquinas.

    Args:
        org_id: Organização (padrão: a configurada/única; "all" para todas).
        severidade: critica, nao_critica, importante, moderada, baixa, nao_especificada, outra
            (ou Critical, -Critical, Important, Moderate, Low, Unspecified, Other).
        status_aprovacao: New, Approved, Declined ou -Declined (todas menos recusadas).
        busca: Texto procurado em qualquer campo (nome, KB, fabricante...).
        apenas_mais_recentes: Exclui atualizações substituídas por outras mais novas.
        completo: True devolve o objeto bruto da API.
        ordenar: Campo de ordenação (ex. "name").
        max_registros: Máximo de pacotes.
    """
    try:
        org = await resolver_org(org_id, permitir_all=True)
        sev = _mapear(severidade, _SEVERIDADE_UPDATE, "severidade")
    except Action1Erro as e:
        return e.como_dict()
    params = {
        "security_severity": sev,
        "approval_status": status_aprovacao,
        "filter": busca,
        "only_latest": _sim_nao(apenas_mais_recentes),
        "sortby": ordenar,
    }
    r = await consultar(montar_rota("updates/{orgId}", orgId=org), params, True, max_registros, limite_chars=10**12)
    if "erro" not in r and not completo:
        r["dados"] = [_compactar_update(u) for u in r["dados"] if isinstance(u, dict)]
    return _finalizar(r)


@mcp.tool()
async def listar_softwares(
    org_id: str | None = None,
    maquina_id: str | None = None,
    busca: str | None = None,
    max_registros: int = 500,
) -> dict[str, Any]:
    """Inventário de softwares instalados: na organização (com nº de máquinas) ou numa máquina.

    Args:
        org_id: Organização (padrão: a configurada/única; "all" para todas).
        maquina_id: Se informado, lista os softwares dessa máquina (com data e local de instalação).
        busca: Texto procurado (nome, fabricante, versão...).
        max_registros: Máximo de linhas.
    """
    try:
        org = await resolver_org(org_id, permitir_all=not maquina_id)
    except Action1Erro as e:
        return e.como_dict()
    rota = montar_rota("installed-software/{orgId}/data/{endpointId}", orgId=org, endpointId=maquina_id) if maquina_id \
        else montar_rota("installed-software/{orgId}/data", orgId=org)
    r = await consultar(rota, {"filter": busca}, True, max_registros, limite_chars=10**12)
    if "erro" not in r:
        linhas = []
        for row in r["dados"]:
            if not isinstance(row, dict):
                continue
            campos = {k: v for k, v in (row.get("fields") or {}).items() if not k.startswith("_") and k != "order_by"}
            faltando = (row.get("fields") or {}).get("_Missing_Updates")
            if faltando:
                campos["atualizacoes_disponiveis"] = [f.get("version") for f in faltando if isinstance(f, dict)]
            linhas.append(campos)
        r["dados"] = linhas
    return _finalizar(r)


@mcp.tool()
async def listar_automacoes(
    org_id: str | None = None,
    tipo: str = "agendadas",
    execucao_id: str | None = None,
    status: str | None = None,
    maquina_id: str | None = None,
    busca: str | None = None,
    max_registros: int = 100,
) -> dict[str, Any]:
    """Lista automações agendadas, execuções recentes ou o resultado de uma execução por máquina.

    Args:
        org_id: Organização (padrão: a configurada/única; não aceita "all").
        tipo: "agendadas" (políticas e tarefas recorrentes) ou "execucoes" (histórico de execuções).
        execucao_id: Se informado, devolve essa execução e o resultado em cada máquina.
        status: Para execuções: Pending, Stopped, Running, Success, Warning ou Error.
        maquina_id: Para execuções: só as que envolveram essa máquina.
        busca: Texto procurado em qualquer campo.
        max_registros: Máximo de registros.
    """
    try:
        org = await resolver_org(org_id)
    except Action1Erro as e:
        return e.como_dict()
    if execucao_id:
        inst = await consultar(montar_rota("automations/instances/{orgId}/{instanceId}", orgId=org, instanceId=execucao_id))
        if "erro" in inst:
            return inst
        res = await consultar(montar_rota("automations/instances/{orgId}/{instanceId}/endpoint-results",
                                          orgId=org, instanceId=execucao_id),
                              {"filter": busca, "last_status": status}, True, max_registros, limite_chars=10**12)
        saida = {"execucao": inst["dados"], "resultados_por_maquina": res if "erro" in res else res["dados"]}
        if "erro" not in res:
            saida["resumo_status"] = dict(Counter(str(x.get("status")) for x in res["dados"] if isinstance(x, dict)))
            saida["tem_mais"] = res.get("tem_mais", False)
        dados, _ = _caber(saida, MAX_CHARS)
        return dados
    t = tipo.strip().lower()
    if t.startswith("agend") or t.startswith("sched"):
        rota, params = montar_rota("automations/schedules/{orgId}", orgId=org), {"filter": busca}
    elif t.startswith("exec") or t.startswith("inst"):
        rota = montar_rota("automations/instances/{orgId}", orgId=org)
        params = {"filter": busca, "status": status, "endpoint_id": maquina_id}
    else:
        return {"erro": "parametro_invalido", "mensagem": "tipo deve ser 'agendadas' ou 'execucoes'."}
    return _finalizar(await consultar(rota, params, True, max_registros, limite_chars=10**12))


@mcp.tool()
async def consultar_relatorio(
    relatorio: str | None = None,
    org_id: str | None = None,
    busca: str | None = None,
    maquina_id: str | None = None,
    max_registros: int = 500,
) -> dict[str, Any]:
    """Lê os dados de um relatório do Action1 (ou lista os relatórios disponíveis).

    Exemplos de relatório: "Reboot Required", "Antivirus Status", "Missing Windows Critical Updates",
    "Windows Update Status", "OS Information", "Known Exploited Vulnerabilities",
    "Windows 11 Hardware Compatibility", "Installed Windows Updates".

    Args:
        relatorio: Id ou nome (exato ou parcial) do relatório. Vazio = lista o catálogo.
        org_id: Organização (padrão: a configurada/única).
        busca: Texto procurado nas linhas do relatório.
        maquina_id: Só os dados de uma máquina.
        max_registros: Máximo de linhas.
    """
    cat = await consultar("reports/all", {"subtree": "Yes"}, limite_chars=10**12)
    if "erro" in cat:
        return cat
    relatorios = [x for x in (cat["dados"] or {}).get("items", []) if x.get("type") == "Report"]
    if not relatorio:
        return {"relatorios": [{"id": x["id"], "name": x.get("name"), "description": x.get("description")} for x in relatorios]}
    alvo = relatorio.strip().lower()
    achados = [x for x in relatorios if alvo in (x["id"].lower(), str(x.get("name", "")).lower())] or \
              [x for x in relatorios if alvo in str(x.get("name", "")).lower() or alvo in x["id"].lower()]
    if not achados:
        return {"erro": "nao_encontrado", "mensagem": f"Nenhum relatório corresponde a '{relatorio}'.",
                "relatorios": [x.get("name") for x in relatorios]}
    if len(achados) > 1:
        return {"erro": "ambiguo", "mensagem": "Vários relatórios correspondem; repita com o id ou o nome exato.",
                "candidatos": [{"id": x["id"], "name": x.get("name")} for x in achados]}
    rel = achados[0]
    try:
        org = await resolver_org(org_id)
    except Action1Erro as e:
        return e.como_dict()
    r = await consultar(montar_rota("reportdata/{orgId}/{reportId}/data", orgId=org, reportId=rel["id"]),
                        {"filter": busca, "endpoint_id": maquina_id}, True, max_registros, limite_chars=10**12)
    if "erro" in r:
        return r
    r["relatorio"] = {"id": rel["id"], "name": rel.get("name"), "description": rel.get("description")}
    r["dados"] = [
        {**{k: v for k, v in (row.get("fields") or {}).items() if not k.startswith("_")},
         **({"row_id": row["id"]} if row.get("drilldown") else {})}
        for row in r["dados"] if isinstance(row, dict)
    ]
    return _finalizar(r)


@mcp.tool()
async def listar_auditoria(
    data_inicio: str | None = None,
    data_fim: str | None = None,
    eventos: str | None = None,
    busca: str | None = None,
    max_registros: int = 200,
) -> dict[str, Any]:
    """Trilha de auditoria do Action1: logins, acessos remotos, mudanças e chamadas de API.

    Args:
        data_inicio: AAAA-MM-DD (dia em horário de Brasília) ou ISO com hora.
        data_fim: AAAA-MM-DD (inclusivo).
        eventos: Eventos separados por vírgula, ex. "Login,Remote Connect,Remote Disconnect,Create User,POST".
        busca: Texto procurado em qualquer campo (usuário, máquina, rota...).
        max_registros: Máximo de registros (mais recentes primeiro).
    """
    try:
        params = {
            "timefrom": _para_a1(data_inicio, False) if data_inicio else None,
            "timeto": _para_a1(data_fim, True) if data_fim else None,
            "event": eventos,
            "filter": busca,
        }
    except Action1Erro as e:
        return e.como_dict()
    return _finalizar(await consultar("audit/events", params, True, max_registros, limite_chars=10**12))


def _top(contador: Counter, n: int = 10) -> dict[str, int]:
    return dict(contador.most_common(n))


@mcp.tool()
async def resumo_ambiente(
    org_id: str | None = None,
    dias_sem_contato: int = 7,
    incluir_vulnerabilidades: bool = True,
    incluir_atualizacoes: bool = True,
    max_maquinas: int = 5000,
) -> dict[str, Any]:
    """Painel do ambiente: máquinas, patches e vulnerabilidades, com contagens e destaques.

    Conta máquinas por status, conexão, SO, plataforma, versão do agente e grupo; quantas
    precisam reiniciar e quantas estão sem contato; soma atualizações e CVEs por máquina e
    aponta as piores. Resume as atualizações faltando por severidade, aprovação e SLA, e os
    CVEs por severidade, status de remediação, KEV e software.

    Args:
        org_id: Organização (padrão: a configurada/única; "all" para todas).
        dias_sem_contato: Máquinas sem contato há mais que isso entram em "sem_contato".
        incluir_vulnerabilidades: Lê a lista completa de CVEs (pode levar alguns segundos).
        incluir_atualizacoes: Lê a lista completa de atualizações faltando.
        max_maquinas: Teto de máquinas analisadas.
    """
    try:
        org = await resolver_org(org_id, permitir_all=True)
    except Action1Erro as e:
        return e.como_dict()
    r = await consultar(montar_rota("endpoints/managed/{orgId}", orgId=org), {"fields": "*", "limit": 500},
                        True, max_maquinas, limite_chars=10**12)
    if "erro" in r:
        return r
    maquinas = [m for m in r["dados"] if isinstance(m, dict)]
    agora = datetime.now(timezone.utc)
    limite_contato = agora - timedelta(days=dias_sem_contato)

    def contar(chave) -> dict[str, int]:
        return dict(Counter((chave(m) if callable(chave) else m.get(chave)) or "(vazio)" for m in maquinas).most_common())

    sem_contato = []
    for m in maquinas:
        visto = _parse_a1(m.get("last_seen"))
        if visto and visto < limite_contato:
            sem_contato.append({"name": m.get("name"), "last_seen": m.get("last_seen"),
                                "dias": (agora - visto).days, "user": m.get("user")})
    grupos = Counter(g.get("name") for m in maquinas for g in m.get("group_membership") or [] if isinstance(g, dict))

    def _n(m: dict, campo: str, tipo: str) -> int:
        return int((m.get(campo) or {}).get(tipo) or 0) if isinstance(m.get(campo), dict) else 0

    def pior(campo: str) -> list[dict[str, Any]]:
        ordenadas = sorted(maquinas, key=lambda m: (_n(m, campo, "critical"), _n(m, campo, "other")), reverse=True)
        return [{"name": m.get("name"), "criticas": _n(m, campo, "critical"), "outras": _n(m, campo, "other"),
                 "status": m.get("status"), "last_seen": m.get("last_seen")}
                for m in ordenadas[:10] if _n(m, campo, "critical") + _n(m, campo, "other") > 0]

    resumo: dict[str, Any] = {
        "organizacao": org,
        "gerado_em_utc": agora.strftime("%Y-%m-%d %H:%M"),
        "maquinas": {
            "total": len(maquinas),
            "amostra_incompleta": r.get("tem_mais", False),
            "por_status": contar("status"),
            "por_conexao": contar("online_status"),
            "por_status_atualizacao": contar("update_status"),
            "por_status_vulnerabilidade": contar("vulnerability_status"),
            "por_plataforma": contar("platform"),
            "por_sistema": contar("OS"),
            "por_versao_agente": contar("agent_version"),
            "por_grupo": dict(grupos.most_common()),
            "reinicio_pendente": sum(1 for m in maquinas if str(m.get("reboot_required", "")).lower() == "yes"),
            f"sem_contato_ha_mais_de_{dias_sem_contato}_dias": sorted(sem_contato, key=lambda x: -x["dias"]),
            "atualizacoes_faltando_total": {
                "criticas": sum(_n(m, "missing_updates", "critical") for m in maquinas),
                "outras": sum(_n(m, "missing_updates", "other") for m in maquinas),
            },
            "vulnerabilidades_total": {
                "criticas": sum(_n(m, "vulnerabilities", "critical") for m in maquinas),
                "outras": sum(_n(m, "vulnerabilities", "other") for m in maquinas),
            },
            "mais_atualizacoes_faltando": pior("missing_updates"),
            "mais_vulnerabilidades": pior("vulnerabilities"),
        },
        "requisicoes": r["paginas_lidas"],
    }
    avisos: list[str] = []

    if incluir_atualizacoes:
        u = await consultar(montar_rota("updates/{orgId}", orgId=org), {"limit": 500}, True, 10000, limite_chars=10**12)
        if "erro" in u:
            resumo["atualizacoes"] = u
        else:
            versoes = [v for p in u["dados"] if isinstance(p, dict) for v in p.get("versions") or [] if isinstance(v, dict)]
            resumo["atualizacoes"] = {
                "pacotes": len(u["dados"]),
                "por_severidade": dict(Counter(v.get("security_severity") or "(vazio)" for v in versoes).most_common()),
                "por_aprovacao": dict(Counter(v.get("approval_status") or "(vazio)" for v in versoes).most_common()),
                "por_sla": dict(Counter(v.get("update_sla_status") or "(vazio)" for v in versoes).most_common()),
                "por_tipo": dict(Counter(p.get("update_type") or "(vazio)" for p in u["dados"]).most_common()),
                "por_fabricante": _top(Counter(p.get("vendor") or "(vazio)" for p in u["dados"])),
                "criticas": [
                    {"name": p.get("name"), "kb_number": p.get("kb_number"),
                     "sla": (p.get("versions") or [{}])[0].get("update_sla_status")}
                    for p in u["dados"]
                    if any(v.get("security_severity") == "Critical" for v in p.get("versions") or [])
                ][:20],
            }
            resumo["requisicoes"] += u["paginas_lidas"]
            if u.get("tem_mais"):
                avisos.append("Atualizações: parou em 10000 pacotes.")

    if incluir_vulnerabilidades:
        v = await consultar(montar_rota("vulnerabilities/{orgId}", orgId=org), {"limit": 500}, True, 50000, limite_chars=10**12)
        if "erro" in v:
            resumo["vulnerabilidades"] = v
        else:
            cves = [x for x in v["dados"] if isinstance(x, dict)]
            produtos: Counter = Counter()
            for x in cves:
                for s in x.get("software") or []:
                    produtos[s.get("product_name") or "(vazio)"] += 1
            kev = [x for x in cves if str(x.get("cisa_kev", "")).lower() == "yes"]
            resumo["vulnerabilidades"] = {
                "cves_distintos": len(cves),
                "por_severidade_cvss": dict(Counter(_severidade_cvss(x.get("cvss_score")) or "(sem nota)" for x in cves).most_common()),
                "por_status_remediacao": dict(Counter(x.get("remediation_status") or "(vazio)" for x in cves).most_common()),
                "cisa_kev": len(kev),
                "kev_lista": sorted((_compactar_vuln(x) for x in kev), key=lambda x: -_score(x.get("cvss_score")))[:20],
                "produtos_com_mais_cves": _top(produtos, 15),
                "mais_graves": [
                    {"cve_id": x.get("cve_id"), "cvss_score": x.get("cvss_score"), "cisa_kev": x.get("cisa_kev"),
                     "endpoints_count": x.get("endpoints_count"), "remediation_status": x.get("remediation_status"),
                     "produtos": [s.get("product_name") for s in x.get("software") or []]}
                    for x in sorted(cves, key=lambda x: -_score(x.get("cvss_score")))[:15]
                ],
            }
            resumo["requisicoes"] += v["paginas_lidas"]
            if v.get("tem_mais"):
                avisos.append("Vulnerabilidades: parou em 50000 CVEs.")

    if r.get("tem_mais"):
        avisos.append(f"Parou em {max_maquinas} máquinas; aumente max_maquinas para analisar todas.")
    if avisos:
        resumo["avisos"] = avisos
    dados, aviso = _caber(resumo, MAX_CHARS)
    if aviso and isinstance(dados, dict):
        dados.setdefault("avisos", []).append(aviso)
    return dados


@mcp.resource("action1://rotas", mime_type="text/markdown")
def recurso_rotas() -> str:
    """ENDPOINTS.md: mapeamento completo da API do Action1."""
    return ENDPOINTS_MD.read_text(encoding="utf-8")


def main() -> None:
    """Ponto de entrada do comando `action1-mcp-server` (transporte stdio)."""
    mcp.run()


if __name__ == "__main__":
    main()
