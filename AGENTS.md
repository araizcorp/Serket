# AGENTS.md — Serket

Guía para agentes de código (Codex, Claude Code, etc.) que trabajen en este repositorio.

## Qué es Serket

**Serket** (`araizcorp-serket`, v2.1.0) — *Silent Active Directory Attack Path Mapper* de AraizCorp LLC.
Herramienta de análisis de rutas de ataque en Active Directory: recolecta vía LDAP/LDAPS
(objetos, ACLs, AD CS, SYSVOL, superficie externa), construye un grafo y calcula rutas de
escalada de privilegios, con workbench local (FastAPI + UI estática) para explorar los
resultados sin enviar nada a terceros. Todo el análisis es local.

> ⚠ **USO EXCLUSIVAMENTE AUTORIZADO.** Solo ejecutar contra sistemas propios o con
> autorización escrita explícita del titular. El uso no autorizado contra terceros es ilegal.

## Setup de desarrollo

```bash
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[test]"   # Git Bash / Windows
./.venv/Scripts/python.exe -m pytest -q                  # suite completa
```

- Python 3.12+, gestión de deps con `pyproject.toml` (setuptools). No hay `requirements.txt` canónico.
- Ejecutable de consola: `serket` (= `serket.cli:main`).
- El punto de entrada del repo es `serket.py` (script raíz, usado por PyInstaller).

## Uso CLI

```bash
# Recolección contra un DC
serket -dc 192.168.4.2 -d it.gcb.local -u itemployee22 -p 'PASSWORD' -o gcbtech_serket

# Con hash NT en vez de contraseña
serket -dc <dc> -d <domain> -u <user> --hashes LM:NT -o out

# Analizar un bundle ya recolectado / servir el workbench
serket --load gcbtech_serket
serket --serve gcbtech_serket [--port 8080]
```

Notas operativas de campo:
- Si 88/389/636 están filtrados (firewall host-based), Serket no puede autenticarse desde fuera.
  Lanza el binario **desde un foothold Windows** del dominio, p. ej. vía share RDP:
  `\\tsclient\<share>\serket.exe -dc <DC_real> -d <domain> ...` — el DC al que hay que apuntar
  es el que resuelve `nltest /dsgetdc:<domain>` (puede no ser el host comprometido).
- `--rate-limit` / `--jitter` controlan la "silenciosidad" de la recolección LDAP.

## Build del exe (Windows, un solo binario)

```bash
./.venv/Scripts/python.exe -m pip install pyinstaller
./.venv/Scripts/python.exe -m PyInstaller serket.spec --noconfirm
# resultado: dist/serket.exe (~25 MB, onefile)
```

**Lecciones ya pagadas (no reintroducir):**
- `serket.spec` incluye `--hidden-import Crypto.Hash.MD4` y los `jaraco.*`/`more_itertools`.
  Sin ellos el exe falla al arrancar.
- El venv necesita **setuptools ≥ 84** (o cualquiera sin `pkg_resources` roto): setuptools 65
  hacía que el runtime hook `pyi_rth_pkgres` petara en Python 3.12. Si el exe falla con
  `jaraco`/`ImpImporter`, limpiar `build/` y `dist/` y recompilar tras actualizar setuptools.
- **MD4**: ldap3 deriva el NT hash con `hashlib.new('MD4', ...)`. En runtimes con OpenSSL 3
  sin legacy provider eso lanza `ValueError: unsupported hash type MD4`. La cadena de
  fallback vive en `serket/_md4.py` (importada desde `serket/__init__.py`, que llama a
  `ensure_md4()`): ① hashlib nativo → ② pycryptodome (dep declarada) → ③ MD4 puro RFC 1320
  vendoreado, registrado en `hashlib.new`. No quitar el hook ni la dependencia.
- Test canónico: `tests/test_md4.py` (vectores RFC 1320 + NT("password")). Debe dar 4/4.

## Arquitectura (mapa rápido)

```
serket.py               entry point (también raíz del spec de PyInstaller)
serket/cli.py           argparse, orquestación, modos server/enrich/external-enrich
serket/_md4.py          fallback MD4 (ver arriba) — NO es lógica de negocio
serket/collector/       ldap_collector.py (LDAP), acl_parser.py, adcs_analysis.py,
                        sysvol.py, external_surface.py
serket/graph/           builder.py (grafo networkx), pathfinder.py (rutas de ataque)
serket/finding_engine.py + finding.py + detection_catalog.py + sensitivity.py
                        motor de findings/detecciones y sensibilidad
serket/enrichment.py    enriquecimiento (keyring, bridges locales)
serket/external_surface.py, discovery.py   superficie externa / descubrimiento
serket/server/          API FastAPI (workbench local)
serket/output/          serialización del bundle de salida
serket/ui/              workbench estático (HTML/CSS/JS)
tests/                  pytest; 2 tests (keyring_enrichment, portico_integration)
                        requieren httpx — instalar con ".[test]"
```

Flujo: `cli.py` → `collector/` (LDAP/SYSVOL/ADCS) → `graph/builder.py` →
`graph/pathfinder.py` + `finding_engine.py` → `output/` (bundle) → `server/` (workbench).

## Reglas para el agente

- No commits masivos (`git add -A`): el repo suele tener trabajo sin commitear del usuario.
  Commits acotados, mensaje en inglés, explicando el porqué.
- No tocar `serket/ui/*` ni `serket/cli.py` salvo petición expresa (trabajo en curso del dueño).
- Todo cambio en `_md4.py` debe pasar `tests/test_md4.py`.
- Respuestas al usuario en español.
