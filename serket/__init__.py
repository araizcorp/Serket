"""
Serket — Active Directory Relationship Intelligence
AraizCorp LLC | Authorized security work only
"""

__version__ = "2.1.0"
__author__ = "AraizCorp LLC"
__license__ = "MIT"

# OpenSSL 3 runtimes without the legacy provider lack MD4, which ldap3 needs
# for NTLM. Make sure a working MD4 exists before anything touches LDAP.
from serket._md4 import ensure_md4 as _ensure_md4

_ensure_md4()
