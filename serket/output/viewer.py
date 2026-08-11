"""
viewer.py — Rich terminal display for Serket results.

AraizCorp LLC — Serket
"""
from __future__ import annotations

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

console = Console()

# ── OPSEC color mapping ───────────────────────────────────────────────────────
_NOISE_COLOR = {"low": "green", "medium": "yellow", "high": "red"}
_EDGE_COLOR  = {
    "Kerberoastable":          "bright_yellow",
    "ASREPRoastable":          "yellow",
    "UnconstrainedDelegation": "bright_red",
    "DCSync":                  "bright_red",
    "ADCS_ESC1":               "bright_magenta",
    "GenericAll":              "red",
    "WriteDACL":               "orange3",
    "WriteOwner":              "orange3",
    "ForceChangePassword":     "orange3",
    "AddMember":               "orange1",
    "ShadowCredentials":       "magenta",
    "MemberOf":                "dim white",
    "RBCD":                    "cyan",
    "ConstrainedDelegation":   "cyan",
    "HasSIDHistory":           "magenta",
}


def _ec(edge_type: str) -> str:
    return _EDGE_COLOR.get(edge_type, "white")


def banner() -> None:
    art = Text()
    lines = [
        "   ██████  ▓█████  ██▀███   ██   ██ ▓█████▄▄▄█████▓",
        "  ▒██   ▒  ▓█   ▀ ▓██ ▒ ██▒ ██▄██▒ ▓█   ▀▓  ██▒ ▓▒",
        "   ▓██▄    ▒███   ▓██ ░▄█ ▒ ▓████▒  ▒███  ▒ ▓██░ ▒░",
        "   ▒   ██▒ ▒▓█  ▄ ▒██▀▀█▄  ▓██  ██▄ ▒▓█  ▄░ ▓██▓ ░ ",
        " ▒██████▒▒ ░▒████▒░██▓ ▒██▒▒██▒ ▀█▒ ░▒████▒ ▒██▒ ░  ",
    ]
    styles = ["bold bright_white", "bold white", "white", "dim white", "dim white"]
    for line, style in zip(lines, styles):
        art.append(line + "\n", style=style)

    body = Text(justify="center")
    body.append("\n  Silent AD Attack Path Mapper", style="bold bright_white")
    body.append("  ·  ", style="dim white")
    body.append("AraizCorp LLC", style="bold red")
    body.append("  ·  ", style="dim white")
    body.append("v2.0\n", style="dim white")

    body.append("\n  ", style="")
    body.append("⚠  USO EXCLUSIVAMENTE AUTORIZADO", style="bold yellow")
    body.append(" — se requiere autorización escrita previa.\n", style="dim white")
    body.append(
        "  Esta herramienta solo puede ejecutarse en sistemas propios o con permiso\n"
        "  explícito y por escrito del titular. El uso no autorizado contra terceros\n"
        "  es ilegal. AraizCorp LLC no asume responsabilidad por usos ilegales.\n",
        style="dim red",
    )

    console.print(Panel(
        Align.center(Text.assemble(art, body)),
        box=box.DOUBLE_EDGE,
        border_style="bright_white",
        padding=(0, 2),
    ))


def show_collection_summary(ad_data: dict, graph_stats: dict) -> None:
    console.print(Rule("[bold white]Collection Summary[/]", style="white"))

    tbl = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    tbl.add_column(style="dim white", justify="right")
    tbl.add_column(style="bold white")

    domain = ad_data.get("domain", {})
    tbl.add_row("Domain",     f"[bold cyan]{domain.get('name', '?')}[/]")
    tbl.add_row("Base DN",    f"[dim]{domain.get('dn', '?')}[/]")
    tbl.add_row("SID",        f"[dim]{domain.get('sid', '?')}[/]")
    tbl.add_row("MachineAccountQuota", str(domain.get("maq", "?")))
    tbl.add_row("Lockout threshold", str(domain.get("lockout_threshold", "?")))
    console.print(tbl)

    obj_tbl = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 3))
    obj_tbl.add_column("Object Type",  style="bold white",  min_width=16)
    obj_tbl.add_column("Count",        style="cyan",         justify="right")
    obj_tbl.add_column("In Graph",     style="dim white",    justify="right")

    by_type = graph_stats.get("by_type", {})
    rows = [
        ("Users",         len(ad_data.get("users", {})),     by_type.get("User", 0)),
        ("Groups",        len(ad_data.get("groups", {})),    by_type.get("Group", 0)),
        ("Computers",     len(ad_data.get("computers", {})), by_type.get("Computer", 0)),
        ("ADCS Templates",len(ad_data.get("adcs", {}).get("templates", [])), by_type.get("CertTemplate", 0)),
        ("GPOs",          len(ad_data.get("gpos", [])),      "-"),
        ("Trusts",        len(ad_data.get("trusts", [])),    "-"),
    ]
    for label, count, in_graph in rows:
        obj_tbl.add_row(label, str(count), str(in_graph))

    console.print(obj_tbl)
    console.print(
        f"  [dim white]Graph:[/] [bold white]{graph_stats['nodes']}[/] nodes  "
        f"[bold white]{graph_stats['edges']}[/] edges  "
        f"[bold yellow]{graph_stats['high_value']}[/] high-value targets\n"
    )


def show_attack_surface(surface: dict) -> None:
    console.print(Rule("[bold red]Attack Surface[/]", style="red"))

    # ── Kerberoastable ────────────────────────────────────────────────────────
    kerb = surface.get("kerberoastable", [])
    if kerb:
        tbl = Table(title="Kerberoastable Users", box=box.SIMPLE_HEAD,
                    title_style="bold yellow", show_header=True, padding=(0, 2))
        tbl.add_column("Account",     style="bold white")
        tbl.add_column("SPNs",        style="dim cyan")
        tbl.add_column("AdminCount",  style="yellow", justify="center")
        for u in kerb:
            spn_txt = ", ".join(u["spns"][:2])
            if len(u["spns"]) > 2:
                spn_txt += f" (+{len(u['spns'])-2})"
            tbl.add_row(u["name"], spn_txt, str(u["admin_count"]))
        console.print(tbl)

    # ── ASREPRoastable ────────────────────────────────────────────────────────
    asrep = surface.get("asreproastable", [])
    if asrep:
        names = ", ".join(u["name"] for u in asrep)
        console.print(f"  [bold yellow]⚡ ASREPRoastable ({len(asrep)}):[/] {names}\n")

    # ── Unconstrained delegation ──────────────────────────────────────────────
    unc = [u for u in surface.get("unconstrained", []) if not u.get("is_dc")]
    if unc:
        names = ", ".join(f"{u['name']} [{u['type']}]" for u in unc)
        console.print(f"  [bold red]⚡ Unconstrained Delegation ({len(unc)}) — non-DC:[/] {names}\n")

    # ── DCSync rights ─────────────────────────────────────────────────────────
    dcsync = surface.get("dcsync", [])
    if dcsync:
        tbl = Table(title="DCSync Rights (non-default)", box=box.SIMPLE_HEAD,
                    title_style="bold red", padding=(0, 2))
        tbl.add_column("Principal", style="bold white")
        tbl.add_column("On Object",  style="dim red")
        for d in dcsync:
            tbl.add_row(d["name"], d["target"])
        console.print(tbl)

    # ── ADCS ESC1 ─────────────────────────────────────────────────────────────
    esc1 = surface.get("adcs_esc1", [])
    if esc1:
        console.print(f"\n  [bold magenta]⚡ ADCS ESC1 — Certificate Impersonation ({len(esc1)} enrollment):[/]")
        for e in esc1:
            console.print(
                f"    [dim]·[/] [white]{e['enroller']}[/] can enroll in "
                f"[bold magenta]{e['template']}[/] "
                f"[dim]→ impersonate any domain user[/]"
            )
        console.print()

    # ── ACL abuses ────────────────────────────────────────────────────────────
    acl = surface.get("acl_abuse", [])
    hv_acl = [a for a in acl if a.get("target_high_value")]
    if hv_acl:
        tbl = Table(title="ACL Abuses on High-Value Targets", box=box.SIMPLE_HEAD,
                    title_style="bold red", padding=(0, 2))
        tbl.add_column("Principal",   style="bold white")
        tbl.add_column("Edge",        style="yellow")
        tbl.add_column("Target",      style="bold red")
        for a in hv_acl[:15]:
            tbl.add_row(a["name"], a["edge"], a["target_name"])
        console.print(tbl)

    # ── RBCD ─────────────────────────────────────────────────────────────────
    rbcd = surface.get("rbcd", [])
    if rbcd:
        console.print(f"\n  [bold cyan]RBCD ({len(rbcd)} entries):[/]")
        for r in rbcd[:8]:
            console.print(f"    [dim]·[/] [white]{r['trustee']}[/] → [cyan]{r['target']}[/]")
        console.print()

    # ── Trusts ────────────────────────────────────────────────────────────────
    trusts = surface.get("trusts", [])
    if trusts:
        console.print(f"\n  [bold white]Domain Trusts ({len(trusts)}):[/]")
        for t in trusts:
            console.print(
                f"    [dim]·[/] [white]{t['partner']}[/] "
                f"[dim]({t['direction']})[/]"
            )
        console.print()


def show_paths(result: dict, max_display: int = 10) -> None:
    paths = result.get("paths", [])
    if not paths:
        console.print(Rule("[dim white]No attack paths found[/]", style="dim white"))
        return

    console.print(Rule(f"[bold red]Attack Paths ({len(paths)} found)[/]", style="red"))

    for i, path in enumerate(paths[:max_display], 1):
        noise_color = "green" if path["noise"] <= 3 else ("yellow" if path["noise"] <= 6 else "red")
        noise_label = "LOW" if path["noise"] <= 3 else ("MEDIUM" if path["noise"] <= 6 else "HIGH")

        header = Text()
        header.append(f"  PATH {i}  ", style="bold white on red")
        header.append("  ", style="")
        header.append(f"{path['src_name']} [{path['src_type']}]", style="bold white")
        header.append(" → ", style="dim white")
        header.append(f"{path['target_name']}", style="bold red")
        header.append(f"  ({path['hops']} hops)  ", style="dim white")
        header.append(f"OPSEC: {noise_label}", style=f"bold {noise_color}")
        console.print(header)

        tree = Tree(
            f"[bold white]{path['src_name']}[/] [{path['src_type']}]",
            guide_style="dim white",
        )
        current = tree
        for step in path["steps"]:
            ec        = _ec(step["edge_type"])
            edge_txt  = f"[{ec}]──[{step['edge_type']}]──>[/]"
            node_txt  = f"[bold white]{step['tgt_name']}[/] [{step['tgt_type']}]"
            detail    = f" [dim]{step['detail']}[/]" if step.get("detail") else ""
            mitre_txt = ""
            if step.get("mitre"):
                mitre_txt = f" [dim white]({step['mitre']['id']})[/]"

            label   = Text.from_markup(f"{edge_txt} {node_txt}{detail}{mitre_txt}")
            current = current.add(label)

        console.print(tree)
        console.print()


def show_adcs_detail(ad_data: dict) -> None:
    adcs = ad_data.get("adcs", {})
    cas  = adcs.get("cas", [])
    tmpl = adcs.get("templates", [])

    if not cas and not tmpl:
        console.print("[dim]  No ADCS infrastructure found.[/]\n")
        return

    console.print(Rule("[bold magenta]ADCS Certificate Services[/]", style="magenta"))

    if cas:
        console.print(f"  [bold white]Certificate Authorities ({len(cas)}):[/]")
        for ca in cas:
            console.print(f"    [magenta]·[/] [white]{ca['name']}[/]  [dim]{ca.get('dns', '')}[/]")
        console.print()

    esc1 = [t for t in tmpl if t.get("esc1")]
    other = [t for t in tmpl if not t.get("esc1")]

    if esc1:
        console.print(f"  [bold red]ESC1 Vulnerable Templates ({len(esc1)}):[/]")
        for t in esc1:
            console.print(
                f"    [bright_red]⚡[/] [white]{t['name']}[/]\n"
                f"       EKUs: [dim]{', '.join(t.get('ekus', [])[:3])}[/]\n"
                f"       Enrollers: [yellow]{len(t.get('enroll_sids', []))} principals[/]"
            )
        console.print()

    if other:
        console.print(f"  [dim]Other templates: {len(other)} (no ESC1)[/]\n")


def show_trusts(ad_data: dict) -> None:
    trusts = ad_data.get("trusts", [])
    if not trusts:
        return
    console.print(Rule("[bold white]Domain Trusts[/]", style="white"))
    tbl = Table(box=box.SIMPLE_HEAD, show_header=True, padding=(0, 2))
    tbl.add_column("Partner",    style="bold white")
    tbl.add_column("Direction",  style="cyan")
    tbl.add_column("Type",       style="dim white")
    for t in trusts:
        tbl.add_row(t["partner"], t["direction"], str(t.get("trust_type", "")))
    console.print(tbl)
    console.print()
