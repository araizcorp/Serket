#!/usr/bin/env python3
"""
Serket — Silent AD Attack Path Mapper  v2.0
AraizCorp LLC | Authorized Security Testing Only

Usage:
  serket -d corp.local -u jdoe --ldaps
  serket -d corp.local -u jdoe --hashes :aad3b435b51404eeaad3b435b51404ee
  serket -d corp.local -u jdoe -k
  serket server
  serket server -d corp.local
  serket --load results/serket_corp_20260101_120000
  serket --serve results/serket_corp_20260101_120000
"""

import argparse
import getpass
import os
from pathlib import Path
import re
import sys

from rich.console import Console
from rich.prompt  import Prompt
from rich.status  import Status

from serket.collector.ldap_collector import LDAPCollector
from serket.collector.sysvol import collect_sysvol
from serket.discovery                  import (
    DomainControllerDiscoveryError,
    discover_domain_controller,
)
from serket.graph.builder            import ADGraph
from serket.graph.pathfinder         import Pathfinder
from serket.output.viewer            import (
    banner, show_collection_summary, show_attack_surface,
    show_paths, show_adcs_detail, show_trusts, console,
)
from serket.output.saver import save_results, load_results, reconstruct_graph

DEFAULT_OUTPUT = os.path.expanduser("~/.serket/results")


def _configure_stdio() -> None:
    """Keep Unicode terminal output from aborting on legacy console encodings."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not reconfigure:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (LookupError, OSError):
            pass


# ── Argument parser ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="serket",
        description="Serket — Silent AD Attack Path Mapper v2.0 | AraizCorp LLC",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument(
        "command", nargs="?", choices=["server", "enrich", "external-enrich"],
        metavar="{server,enrich,external-enrich}",
        help="Open the web UI or apply a sanitized enrichment bridge",
    )
    auth = p.add_argument_group("Authentication")
    auth.add_argument(
        "-dc", "--dc", metavar="HOST",
        help="DC hostname or IP (optional; discovered from AD DNS by default)",
    )
    auth.add_argument(
        "-d", "--domain", metavar="DOMAIN",
        help="Domain FQDN for collection or saved-result selection",
    )
    auth.add_argument("-u",   "--user",     metavar="USER",   help="Username")
    auth.add_argument("-p",   "--password", metavar="PASS",   help="Password (omit to prompt)")
    auth.add_argument("--hashes",           metavar="LM:NT",  help="NTLM hashes (LM:NT or just :NT)")
    auth.add_argument("-k",  "--kerberos",  action="store_true", help="Use Kerberos (KRB5CCNAME)")
    auth.add_argument("--ldaps",            action="store_true", help="Use LDAPS (port 636)")

    opt = p.add_argument_group("Options")
    opt.add_argument("--rate-limit",  type=float, default=0.08, metavar="SEC",
                     help="Seconds between LDAP pages (default: 0.08)")
    opt.add_argument("--max-paths",   type=int,   default=20,
                     help="Maximum attack paths to compute (default: 20)")
    opt.add_argument("--no-acls",     action="store_true",
                     help="Skip ACL collection (faster, fewer edges)")
    opt.add_argument("--no-adcs",     action="store_true",
                     help="Skip ADCS template enumeration")
    opt.add_argument(
        "--sysvol-root", metavar="PATH",
        help="Parse an explicitly supplied local/mounted SYSVOL copy (no share discovery)",
    )
    opt.add_argument(
        "--include-external-surface", action="store_true",
        help="Explicitly run standalone Portico from PATH and consume its sanitized bridge",
    )
    opt.add_argument("-o", "--output", default=DEFAULT_OUTPUT, metavar="PATH",
                     help=f"Output directory, or FILE.serket for enrich (default: {DEFAULT_OUTPUT})")
    opt.add_argument("--load", metavar="PATH",
                     help="Load a result bundle, manifest, or legacy results JSON")
    opt.add_argument("--serve", metavar="PATH",
                     help="Launch the web UI from a bundle, manifest, or legacy JSON")
    opt.add_argument("--input", metavar="PATH",
                     help="Input .serket package for the enrich command")
    opt.add_argument("--bridge", metavar="PATH",
                     help="Keyring or Portico bridge JSON for an enrichment command")
    opt.add_argument("--port", type=int, default=8080,
                     help="Web UI port for server/--serve (default: 8080, always 127.0.0.1)")
    opt.add_argument("--quiet", "-q", action="store_true",
                     help="Suppress progress output (machine-friendly)")

    return p


# ── Interactive credential prompt ─────────────────────────────────────────────

def _prompt_creds(args) -> None:
    if not args.domain:
        args.domain = Prompt.ask("  [cyan]Domain (e.g. corp.local)[/]")
    if not args.user:
        args.user = Prompt.ask("  [cyan]Username[/]")

    if not args.kerberos and not args.hashes and not args.password:
        console.print("  [dim]Auth method:[/]  1=Password  2=NTLM hash  3=Kerberos")
        choice = Prompt.ask("  Choice", choices=["1", "2", "3"], default="1")
        if choice == "1":
            args.password = getpass.getpass("  Password: ")
        elif choice == "2":
            args.hashes   = getpass.getpass("  NTLM hash (LM:NT or :NT): ")
        else:
            args.kerberos = True


# ── Collection pipeline ───────────────────────────────────────────────────────

def _run_collect(args) -> None:
    collector = LDAPCollector(
        dc_host    = args.dc,
        domain     = args.domain,
        username   = args.user,
        password   = getattr(args, "password", None),
        hashes     = getattr(args, "hashes",   None),
        kerberos   = getattr(args, "kerberos", False),
        use_ldaps  = getattr(args, "ldaps",    False),
        rate_limit = args.rate_limit,
    )

    def _progress(stage: str):
        if not args.quiet:
            console.print(f"  [dim white]→ {stage}[/]")

    if not args.quiet:
        with Status("[bold white]Connecting to LDAP...[/]", console=console):
            collector.connect()
        console.print(f"  [green]✓[/] Connected to [bold]{args.dc}[/] as [bold]{args.user}[/]\n")
        console.print("[bold white]Collecting AD objects...[/]")
    else:
        collector.connect()

    ad_data = collector.collect_all(
        progress_cb=_progress,
        include_acls=not args.no_acls,
        include_adcs=not args.no_adcs,
    )
    if args.sysvol_root:
        if not args.quiet:
            console.print("  [dim white]Parsing explicit SYSVOL evidence[/]")
        sysvol = collect_sysvol(args.sysvol_root, ad_data.get("gpos", []))
        ad_data["sysvol"] = sysvol
        ad_data.setdefault("coverage", {})["sysvol"] = {
            "status": sysvol["status"],
            "mode": "explicit_offline",
            "files_parsed": sysvol["files_parsed"],
        }

    if not args.quiet:
        console.print("\n[bold white]Building attack graph...[/]")
    ag    = ADGraph.build_from_data(ad_data)
    stats = ag.stats()

    if not args.quiet:
        console.print(
            f"  [green]✓[/] Graph ready: "
            f"[bold]{stats['nodes']}[/] nodes  "
            f"[bold]{stats['edges']}[/] edges\n"
        )
        with Status("[bold white]Computing attack paths (Dijkstra)...[/]", console=console):
            analysis = Pathfinder.find_all(ag, ad_data, max_paths=args.max_paths)
    else:
        analysis = Pathfinder.find_all(ag, ad_data, max_paths=args.max_paths)

    if args.include_external_surface:
        if not args.quiet:
            console.print("  [dim white]Running optional standalone Portico collector...[/]")
        from networkx.readwrite import json_graph as nx_jg
        from serket.collector.external_surface import collect_external_surface_bridge
        from serket.external_surface import apply_external_bridge

        bridge, external_coverage = collect_external_surface_bridge(args.domain, probe_ldaps=True)
        ad_data.setdefault("coverage", {})["external_surface"] = external_coverage
        if bridge is not None:
            runtime = {
                **ad_data,
                **analysis,
                "meta": {"snapshot_id": analysis.get("snapshot_id", "")},
                "graph": nx_jg.node_link_data(ag.G),
                "high_value": sorted(ag.high_value),
            }
            external_report = apply_external_bridge(runtime, bridge)
            for key in ("findings", "risk_summary", "posture", "snapshot_id", "sensitivity"):
                if key in runtime:
                    analysis[key] = runtime[key]
            ad_data["external_surface_enrichment"] = external_report
            ad_data["coverage"] = runtime.get("coverage", ad_data["coverage"])
            # Copy the sanitized annotations and unmatched ExternalAsset nodes
            # back into the graph that save_results() serializes.
            for node in runtime["graph"].get("nodes", []):
                node_id = node.get("id")
                if node_id in ag.G:
                    ag.G.nodes[node_id].update(node)
                elif node_id:
                    ag.G.add_node(node_id, **{key: value for key, value in node.items() if key != "id"})
        elif not args.quiet:
            console.print(
                f"  [yellow]Portico omitted:[/] {external_coverage.get('reason', 'unavailable')}"
            )
        stats = ag.stats()

    # Pass ag so graph is serialized — enables graph reconstruction on --load / --serve
    out_dir = save_results(ad_data, stats, analysis, args.output, ag=ag)

    if not args.quiet:
        console.print("\n")
        show_collection_summary(ad_data, stats)
        show_attack_surface(analysis["surface"])
        show_adcs_detail(ad_data)
        show_trusts(ad_data)
        show_paths(analysis, max_display=10)
        console.print(f"\n[bold green]✓ Results saved to:[/] [cyan]{out_dir}[/]\n")
        console.print(f"[bold green]Portable package:[/] [cyan]{out_dir}.serket[/]")
        console.print(
            f"  [dim]Tip: launch web UI with:[/]  "
            f"[bold white]serket server -d {args.domain}[/]\n"
        )
    else:
        paths = analysis.get("paths", [])
        print(f"PATHS_FOUND={len(paths)}")
        print(f"OUTPUT_DIR={out_dir}")


# ── Load mode ─────────────────────────────────────────────────────────────────

def _run_load(json_path: str, max_paths: int = 20) -> None:
    data = load_results(json_path)

    # Try to reconstruct the graph and re-run pathfinding with Dijkstra
    ag = reconstruct_graph(data)
    if ag:
        ad_data = {
            "domain":    data.get("domain", {}),
            "users":     {},
            "groups":    {},
            "computers": {},
            "adcs":      data.get("adcs", {}),
            "trusts":    data.get("trusts", []),
            "gpos":      data.get("gpos", []),
        }
        analysis = Pathfinder.find_all(ag, ad_data, max_paths=max_paths)
        surface  = analysis.get("surface", {})
        paths    = analysis.get("paths", [])
        stats    = ag.stats()
    else:
        # Fallback: display saved paths without re-running pathfinding
        surface  = data.get("surface", {})
        paths    = data.get("paths", [])
        stats    = data.get("stats",  {})
        ad_data  = {
            "domain":    data.get("domain", {}),
            "users":     {},
            "groups":    {},
            "computers": {},
            "adcs":      data.get("adcs",   {}),
            "trusts":    data.get("trusts", []),
            "gpos":      data.get("gpos",   []),
        }
        analysis = {"paths": paths, "surface": surface}

    show_collection_summary(ad_data, stats)
    show_attack_surface(surface)
    show_adcs_detail(ad_data)
    show_trusts(ad_data)
    show_paths(analysis)

    meta = data.get("meta", {})
    console.print(
        f"\n[dim]Loaded from: [cyan]{json_path}[/]  "
        f"generated: {meta.get('generated', '?')}[/]\n"
    )


# ── Serve mode ────────────────────────────────────────────────────────────────

def _find_latest_result(output_dir: str, domain: str | None = None) -> str | None:
    """Find the newest complete bundle or legacy JSON for one domain."""
    directory = Path(output_dir).expanduser()
    try:
        candidates = list(directory.iterdir())
    except OSError:
        return None

    prefix = "serket_"
    if domain:
        prefix = f"serket_{domain.replace('.', '_')}_"
    prefix = prefix.casefold()

    results: list[Path] = []
    for path in candidates:
        try:
            is_bundle = (
                path.is_dir()
                and path.name.casefold().startswith(prefix)
                and (path / "manifest.json").is_file()
            )
            is_package = (
                path.is_file()
                and path.name.casefold().startswith(prefix)
                and bool(re.search(r"_\d{8}_\d{6}\.serket$", path.name, re.IGNORECASE))
            )
            is_legacy_json = (
                path.is_file()
                and path.name.casefold().startswith(prefix)
                and bool(re.search(r"_\d{8}_\d{6}\.json$", path.name, re.IGNORECASE))
            )
        except OSError:
            continue
        if not (is_bundle or is_package or is_legacy_json):
            continue
        results.append(path)

    if not results:
        return None
    # Serket filenames end in YYYYMMDD_HHMMSS, which remains reliable when
    # result files are copied between systems and their filesystem mtime changes.
    def collection_stamp(path: Path) -> str:
        match = re.search(r"_(\d{8}_\d{6})(?:\.json|\.serket)?$", path.name, re.IGNORECASE)
        return match.group(1) if match else ""

    return str(max(results, key=lambda path: (collection_stamp(path), path.name)))


def _run_server_command(output_dir: str, domain: str | None, port: int) -> None:
    """Open the latest result, with an optional domain selector."""
    json_path = _find_latest_result(output_dir, domain)
    if not json_path:
        qualifier = f" for domain {domain}" if domain else ""
        console.print(
            f"[red][!] No saved Serket results found{qualifier} in {output_dir}.[/]"
        )
        console.print("  Run a collection first or select its directory with --output.")
        sys.exit(1)
    _run_serve(json_path, port=port)

def _run_serve(json_path: str, port: int = 8080) -> None:
    """Load a saved result bundle or legacy JSON and launch the web UI."""
    if not os.path.exists(json_path):
        console.print(f"[red][!] Result not found: {json_path}[/]")
        sys.exit(1)

    try:
        from serket.server.api import run_server
    except ImportError as e:
        console.print(f"[red][!] Cannot start web UI: {e}[/]")
        console.print("  Install: [bold]pip install fastapi uvicorn[/]")
        sys.exit(1)

    console.print(f"  [dim]Loading:[/] [cyan]{json_path}[/]")
    data = load_results(json_path)

    # Try to reconstruct the graph and re-run pathfinding for fresh analysis
    ag = reconstruct_graph(data)
    if ag:
        ad_data = {
            "domain":    data.get("domain", {}),
            "users":     {},
            "groups":    {},
            "computers": {},
            "adcs":      data.get("adcs", {}),
            "trusts":    data.get("trusts", []),
        }
        analysis = Pathfinder.find_all(ag, ad_data, max_paths=50)
        data["paths"]   = analysis.get("paths", [])
        data["surface"] = analysis.get("surface", {})
        data["stats"]   = ag.stats()
        console.print(
            f"  [green]✓[/] Graph reconstructed — "
            f"[bold]{data['stats']['nodes']}[/] nodes, "
            f"[bold]{len(data['paths'])}[/] paths\n"
        )
    else:
        console.print("  [dim](No graph data found — using saved paths)[/]\n")

    run_server(data, port=port)


def _run_enrich(input_path: str | None, bridge_path: str | None, output_path: str) -> None:
    """Apply Keyring metadata and emit a new portable Serket package."""
    from serket.enrichment import apply_bridge, load_bridge, save_enriched_package

    if not input_path or not bridge_path:
        raise ValueError("serket enrich requires --input and --bridge")
    if Path(output_path).suffix.casefold() != ".serket":
        raise ValueError("serket enrich requires --output FILE.serket")
    if Path(input_path).expanduser().resolve() == Path(output_path).expanduser().resolve():
        raise ValueError("enriched output must not overwrite the input package")
    data = load_results(input_path)
    report = apply_bridge(data, load_bridge(bridge_path))
    destination = save_enriched_package(data, output_path)
    console.print(f"[green]Enriched package written:[/] [cyan]{destination}[/]")
    console.print(
        f"  Matched: [bold]{report['matched']}[/]  "
        f"Unmatched: [bold]{report['unmatched']}[/]  "
        f"Ambiguous: [bold]{report['ambiguous']}[/]"
    )


def _run_external_enrich(input_path: str | None, bridge_path: str | None, output_path: str) -> None:
    """Apply Portico observations and emit a new portable Serket package."""
    from serket.enrichment import save_enriched_package
    from serket.external_surface import apply_external_bridge, load_external_bridge

    if not input_path or not bridge_path:
        raise ValueError("serket external-enrich requires --input and --bridge")
    if Path(output_path).suffix.casefold() != ".serket":
        raise ValueError("serket external-enrich requires --output FILE.serket")
    if Path(input_path).expanduser().resolve() == Path(output_path).expanduser().resolve():
        raise ValueError("enriched output must not overwrite the input package")
    data = load_results(input_path)
    report = apply_external_bridge(data, load_external_bridge(bridge_path))
    destination = save_enriched_package(data, output_path)
    console.print(f"[green]Externally enriched package written:[/] [cyan]{destination}[/]")
    console.print(
        f"  Matched: [bold]{report['matched']}[/]  "
        f"Unmatched: [bold]{report['unmatched']}[/]  "
        f"Ambiguous: [bold]{report['ambiguous']}[/]  "
        f"Findings: [bold]{report['findings']}[/]"
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    _configure_stdio()
    parser = _build_parser()
    args   = parser.parse_args()

    if not args.quiet:
        banner()
        console.print()

    # ── Automatic server mode ─────────────────────────────────────────────────
    if args.command == "server":
        _run_server_command(args.output, args.domain, args.port)
        return

    if args.command == "enrich":
        try:
            _run_enrich(args.input, args.bridge, args.output)
        except (OSError, ValueError) as exc:
            console.print(f"[red][!] Enrichment failed: {exc}[/]")
            sys.exit(2)
        return

    if args.command == "external-enrich":
        try:
            _run_external_enrich(args.input, args.bridge, args.output)
        except (OSError, ValueError) as exc:
            console.print(f"[red][!] External enrichment failed: {exc}[/]")
            sys.exit(2)
        return

    # ── Serve mode ────────────────────────────────────────────────────────────
    if args.serve:
        _run_serve(args.serve, port=args.port)
        return

    # ── Load mode ─────────────────────────────────────────────────────────────
    if args.load:
        if not os.path.exists(args.load):
            console.print(f"[red][!] Result not found: {args.load}[/]")
            sys.exit(1)
        _run_load(args.load, max_paths=args.max_paths)
        return

    # ── Collect mode ──────────────────────────────────────────────────────────
    if not (args.domain and args.user):
        if not args.quiet:
            console.print("[bold white]Enter connection details:[/]\n")
        _prompt_creds(args)

    if not (args.domain and args.user):
        console.print("[red][!] Domain and username are required.[/]")
        sys.exit(1)

    if not args.dc:
        if not args.quiet:
            console.print(f"  [dim]Discovering a domain controller for {args.domain}...[/]")
        try:
            args.dc = discover_domain_controller(args.domain)
        except DomainControllerDiscoveryError as exc:
            console.print(f"[red][!] {exc}[/]")
            sys.exit(1)
        if not args.quiet:
            console.print(f"  [green]✓[/] Discovered DC: [bold]{args.dc}[/]\n")

    if not args.kerberos and not args.hashes and not args.password:
        if not args.quiet:
            args.password = getpass.getpass("  Password: ")
        else:
            console.print("[red][!] Provide --password, --hashes, or -k.[/]")
            sys.exit(1)

    try:
        _run_collect(args)
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted.[/]")
        sys.exit(0)
    except Exception as exc:
        console.print(f"\n[red][!] Fatal error: {exc}[/]")
        if os.environ.get("SERKET_DEBUG"):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
