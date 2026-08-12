#!/usr/bin/env python3
"""
Serket — Silent AD Attack Path Mapper  v2.0
AraizCorp LLC | Authorized Security Testing Only

Usage:
  serket -d corp.local -u jdoe --ldaps
  serket -d corp.local -u jdoe --hashes :aad3b435b51404eeaad3b435b51404ee
  serket -d corp.local -u jdoe -k
  serket --load results/serket_corp_20260101_120000.json
  serket --serve results/serket_corp_20260101_120000.json
"""

import argparse
import getpass
import os
import sys

from rich.console import Console
from rich.prompt  import Prompt
from rich.status  import Status

from serket.collector.ldap_collector import LDAPCollector
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


# ── Argument parser ───────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="serket",
        description="Serket — Silent AD Attack Path Mapper v2.0 | AraizCorp LLC",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    auth = p.add_argument_group("Authentication")
    auth.add_argument(
        "-dc", "--dc", metavar="HOST",
        help="DC hostname or IP (optional; discovered from AD DNS by default)",
    )
    auth.add_argument("-d",   "--domain",   metavar="DOMAIN", help="Domain FQDN (corp.local)")
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
    opt.add_argument("-o", "--output", default=DEFAULT_OUTPUT, metavar="DIR",
                     help=f"Output directory (default: {DEFAULT_OUTPUT})")
    opt.add_argument("--load", metavar="JSON",
                     help="Load and display a previously saved results JSON")
    opt.add_argument("--serve", metavar="JSON",
                     help="Launch interactive web UI from a saved results JSON")
    opt.add_argument("--port", type=int, default=8080,
                     help="Web UI port for --serve (default: 8080, always 127.0.0.1)")
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

    ad_data  = collector.collect_all(progress_cb=_progress)

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
        console.print(
            f"  [dim]Tip: launch web UI with:[/]  "
            f"[bold white]serket --serve {out_dir}/*.json[/]\n"
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

def _run_serve(json_path: str, port: int = 8080) -> None:
    """Load a saved JSON result and launch the interactive web UI."""
    if not os.path.isfile(json_path):
        console.print(f"[red][!] File not found: {json_path}[/]")
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


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = _build_parser()
    args   = parser.parse_args()

    if not args.quiet:
        banner()
        console.print()

    # ── Serve mode ────────────────────────────────────────────────────────────
    if args.serve:
        _run_serve(args.serve, port=args.port)
        return

    # ── Load mode ─────────────────────────────────────────────────────────────
    if args.load:
        if not os.path.isfile(args.load):
            console.print(f"[red][!] File not found: {args.load}[/]")
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
