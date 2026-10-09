"""MD4 fallback tests.

These matter on runtimes where OpenSSL 3 ships without the legacy provider
(hashlib has no native MD4). In that case importing ``serket`` installs the
vendored implementation behind ``hashlib.new`` and these tests verify both
the implementation itself and the shim ldap3 relies on.
"""

import hashlib

import serket  # noqa: F401  — import side effect: installs MD4 shim if needed


def test_md4_rfc1320_vectors():
    from serket._md4 import MD4

    assert MD4(b"").hexdigest() == "31d6cfe0d16ae931b73c59d7e0c089c0"
    assert MD4(b"abc").hexdigest() == "a448017aaf21d8525fc10ae87aa6729d"


def test_md4_ntlm_derived_nt_hash():
    from serket._md4 import MD4

    # MD4(UTF-16LE("password")) is the NT hash used by NTLMv2.
    nt = MD4("password".encode("utf-16-le")).hexdigest()
    assert nt == "8846f7eaee8fb117ad06bdd830b7586c"


def test_hashlib_new_serves_md4_for_ldap3():
    # ldap3 calls hashlib.new('MD4', data) during NTLM auth; after importing
    # serket this must work even without the OpenSSL legacy provider.
    assert hashlib.new("MD4", b"abc").hexdigest() == "a448017aaf21d8525fc10ae87aa6729d"


def test_md4_incremental_updates_and_metadata():
    from serket._md4 import MD4

    incremental = MD4()
    incremental.update(b"ab")
    incremental.update(b"c")
    assert incremental.hexdigest() == MD4(b"abc").hexdigest()
    assert incremental.digest_size == 16
    assert incremental.block_size == 64
    assert incremental.name == "md4"
