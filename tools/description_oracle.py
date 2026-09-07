# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""
Independent oracle for C18 — the signed description / directory primitive (design.md §21).

C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own
signed object: the authority lives in the signed bytes, never in the connection that served them.
Three wire objects:

  * naalp-description   {1: service, 2: [* operation]} — a service lists its operations, each an
    operation {1: name, 2: effect, 3: requires_approval}. It re-verifies byte-identically when an
    unrelated host serves the same bytes (a bearer credential, not a fetched document).
  * naalp-directory     {1: directory, 2: version, 3: [* member-content-id]} — a signed collection
    whose members are content-ids (the same list-of-content-ids shape the audit/causes partial order
    uses). Two conflicting versions from ONE signer (same directory + version, different members) are
    a FORK, detected at the FIRST-DIFFERING member position (as the audit fork-proof reports position).
  * naalp-description-import {1: importer, 2: format, 3: foreign, 4: [* operation]} — a foreign
    description format (A2A Agent Card / ANP Agent Description / AGNTCY Agent Badge) carried
    octet-for-octet (carriage, not adoption) as a signed N-AALP attestation binding the foreign
    bytes' content-id AND an N-AALP effect mapping. The IMPORTER (the wrapping signer) is the sole
    authorization identity; a foreign identity inside `foreign` never becomes one (confused-deputy
    containment, the same rule as the MCP profile §19 and foreign carriage R-14.6).

Non-circular authority (NOT the code under test):
  * Every object body is built by the shared deterministic-CBOR constructor (cbor_oracle, graded
    against RFC 8949 in T1) — never by the Go/Rust description code.
  * The content-id framing is the T1 multihash: 0x20 0x30 || SHA-384(canonical body) (design §2.3),
    computed here with standard-library hashlib.
  * The head of a directory / description / import is SHA-384(body) (48 octets), the same
    construction as the C7 audit receipt head — computed here with hashlib, independent of the impl.
  * The four-effect lattice values (read_only=0 < idempotent_write=1 < non_idempotent_write=2 <
    destructive=3) and requires_approval as the uint 1/0 (the N-AALP spine carries no CBOR boolean,
    design §3.1) are behavioural properties graded in Go and Rust; this oracle fixes the body + head
    + id bytes so Go == oracle == Rust, and fixes the fork / confused-deputy inputs so both
    implementations resolve them identically. ML-DSA signatures over the signed objects are
    deterministic (FIPS 204, empty context) and cross-checked Go == Rust in the impl tests; Python
    stdlib has no ML-DSA, so this oracle fixes only the SIGNED INPUT (the body bytes), not the
    signature.

Emits vectors/description/cases.json (LF-normalized).
"""
import hashlib
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cbor_oracle  # shared RFC-8949 deterministic-CBOR constructor (graded in T1)

# Effect lattice (design §6; policy.go): read_only < idempotent_write < non_idempotent_write < destructive.
READ_ONLY, IDEMPOTENT_WRITE, NON_IDEMPOTENT_WRITE, DESTRUCTIVE = 0, 1, 2, 3

# Foreign description format codes (design §21; machine-readable naalp-description-format registry).
FMT_A2A_CARD = 1        # A2A Agent Card
FMT_ANP_DESCRIPTION = 2  # ANP Agent Description
FMT_AGNTCY_BADGE = 3     # AGNTCY Agent Badge


def sha384(b):
    return hashlib.sha384(b).digest()


def cid(b):
    """T1 content-id framing: multihash(0x20, SHA-384(bytes)) = 0x20 0x30 || SHA-384(b) (50 octets)."""
    return b"\x20\x30" + sha384(b)


def operation_body(name, effect, requires_approval):
    # {1: name (tstr), 2: effect (uint), 3: requires_approval (uint 1/0 — no CBOR boolean on the spine)}.
    return ("map", [(1, name), (2, effect), (3, requires_approval)])


def description_body(service, operations):
    # {1: service (bstr), 2: [* operation]}.
    ops = [operation_body(*op) for op in operations]
    return cbor_oracle.encode(("map", [(1, service), (2, ops)]))


def directory_body(directory, version, members):
    # {1: directory (bstr), 2: version (uint), 3: [* member content-id (bstr)]}.
    return cbor_oracle.encode(("map", [(1, directory), (2, version), (3, list(members))]))


def import_body(importer, fmt, foreign, operations):
    # {1: importer (bstr), 2: format (uint), 3: foreign (bstr, octet-for-octet), 4: [* operation]}.
    ops = [operation_body(*op) for op in operations]
    return cbor_oracle.encode(("map", [(1, importer), (2, fmt), (3, foreign), (4, ops)]))


def first_differing_member(a, b):
    """The first index at which two member lists differ (the fork position). If they share a common
    prefix and one is longer, the difference is at the length of the shorter list. Returns (-1, False)
    when the lists are identical."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i, True
    if len(a) != len(b):
        return n, True
    return -1, False


def build():
    # ---- Description: a service lists its operations, each with an effect + approval declaration ---
    service = b"svc-billing-0001"
    operations = [
        ("status",       READ_ONLY,            0),  # observe only, no approval
        ("write_record", NON_IDEMPOTENT_WRITE, 1),  # additive write, approval required
        ("purge",        DESTRUCTIVE,          1),  # destructive, approval required
    ]
    desc = description_body(service, operations)
    desc_head = sha384(desc)
    desc_id = cid(desc)
    op_out = []
    for (name, effect, req) in operations:
        ob = cbor_oracle.encode(operation_body(name, effect, req))
        op_out.append({
            "name": name, "effect": effect, "requires_approval": req,
            "body_hex": ob.hex(),
        })

    # ---- Directory: a signed collection whose members are content-ids ----------------------------
    directory = b"dir-catalog-0001"
    version = 7
    members_a = [cid(b"desc-A"), cid(b"desc-B"), cid(b"desc-C")]
    dir_a = directory_body(directory, version, members_a)
    dir_a_head = sha384(dir_a)
    dir_a_id = cid(dir_a)

    # Fork: SAME directory + version from ONE signer, but member[1] differs (desc-B -> desc-X).
    members_b = [cid(b"desc-A"), cid(b"desc-X"), cid(b"desc-C")]
    dir_b = directory_body(directory, version, members_b)
    dir_b_head = sha384(dir_b)
    dir_b_id = cid(dir_b)
    fork_pos, fork_is = first_differing_member(members_a, members_b)
    assert fork_is and fork_pos == 1, "expected a fork at member position 1"

    # Length-mismatch fork: a truncated member list forks at the length of the shorter list.
    members_short = [cid(b"desc-A")]
    dir_short = directory_body(directory, version, members_short)
    short_pos, short_is = first_differing_member(members_a, members_short)
    assert short_is and short_pos == 1, "expected a length-mismatch fork at position 1"

    # Benign duplicate: identical members => NOT a fork (no position).
    dup_pos, dup_is = first_differing_member(members_a, members_a)
    assert (not dup_is) and dup_pos == -1, "identical members must not be a fork"

    # A DIFFERENT version is a legitimate succession, not a fork (guarded in the impl by id+version).
    dir_v8 = directory_body(directory, 8, members_b)

    # ---- Foreign-description import: a signed attestation (carriage, not adoption) ----------------
    # The foreign bytes embed a FOREIGN identity to prove it is never adopted as the authorization
    # identity — the importer (the wrapping signer) is the sole authority (confused-deputy rule).
    importer = b"IMPORTER_ID_A"
    foreign = (b'{"protocolType":"ANP","id":"did:wba:foreign.example:agent",'
               b'"name":"catalog-agent","interfaces":["/query","/submit"]}')
    imp_ops = [
        ("query",  READ_ONLY,        0),
        ("submit", IDEMPOTENT_WRITE, 1),
    ]
    imp = import_body(importer, FMT_ANP_DESCRIPTION, foreign, imp_ops)
    imp_head = sha384(imp)
    imp_id = cid(imp)
    foreign_id = cid(foreign)  # the bound content-id of the foreign bytes

    # ---- Unknown-format reject (C18 audit fix 0d): field 2 is the CLOSED naalp-description-format
    # enum {1,2,3}. A code outside the set (e.g. 99) is well-formed CBOR but not a registered format;
    # both impls MUST reject it UnknownDescriptionFormat on decode, never carry it as an open uint.
    UNKNOWN_FORMAT = 99
    unknown_fmt_body = import_body(importer, UNKNOWN_FORMAT, foreign, imp_ops)

    return {
        "source": ("design §21; naalp-description {1:service,2:[operation]} (full ML-DSA sig; "
                   "operation {1:name,2:effect,3:requires_approval}); naalp-directory "
                   "{1:directory,2:version,3:[member-content-id]} (full ML-DSA sig; fork = same "
                   "directory+version from one signer with differing members, reported at the first-"
                   "differing member position); naalp-description-import {1:importer,2:format,3:foreign,"
                   "4:[operation]} (full ML-DSA sig; carriage octet-for-octet; the importer is the sole "
                   "authorization identity, a foreign identity never becomes one). head = SHA-384(body); "
                   "content-id = multihash(0x20, SHA-384). Effect lattice read_only=0<idempotent_write=1"
                   "<non_idempotent_write=2<destructive=3; requires_approval is uint 1/0 (no CBOR bool)."),
        "description": {
            "service_hex": service.hex(),
            "operations": op_out,
            "body_hex": desc.hex(), "head_hex": desc_head.hex(), "id_hex": desc_id.hex(),
        },
        "directory": {
            "directory_hex": directory.hex(), "version": version,
            "members_a_hex": [m.hex() for m in members_a],
            "a": {"body_hex": dir_a.hex(), "head_hex": dir_a_head.hex(), "id_hex": dir_a_id.hex()},
            "fork": {
                "members_b_hex": [m.hex() for m in members_b],
                "b": {"body_hex": dir_b.hex(), "head_hex": dir_b_head.hex(), "id_hex": dir_b_id.hex()},
                "first_differing_position": fork_pos,
                "note": "same directory+version, member[1] differs (desc-B -> desc-X) => fork at position 1.",
            },
            "length_fork": {
                "members_short_hex": [m.hex() for m in members_short],
                "body_hex": dir_short.hex(),
                "first_differing_position": short_pos,
                "note": "a truncated member list forks at the length of the shorter list (position 1).",
            },
            "different_version": {
                "version": 8, "body_hex": dir_v8.hex(),
                "note": "a different version is a legitimate succession, not a fork.",
            },
            "duplicate_first_differing_position": dup_pos,  # -1 => identical, not a fork
        },
        "import": {
            "importer_hex": importer.hex(),
            "format": FMT_ANP_DESCRIPTION,
            "foreign_hex": foreign.hex(),
            "foreign_id_hex": foreign_id.hex(),
            "operations": [
                {"name": n, "effect": e, "requires_approval": r} for (n, e, r) in imp_ops
            ],
            "body_hex": imp.hex(), "head_hex": imp_head.hex(), "id_hex": imp_id.hex(),
            "foreign_asserted_identity": "did:wba:foreign.example:agent",
            "note": ("the importer (field 1) is the sole authorization identity; the foreign identity "
                     "embedded in field 3 is bound by content-id but never authorizes (R-14.6)."),
            "unknown_format": {
                "format": UNKNOWN_FORMAT,
                "body_hex": unknown_fmt_body.hex(),
                "reject": "UnknownDescriptionFormat",
                "note": "format 99 is outside the closed naalp-description-format set {1,2,3} -> rejected on decode.",
            },
        },
    }


def main():
    data = build()
    out = os.path.join(HERE, "..", "vectors", "description", "cases.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with io.open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=2)
        f.write("\n")
    print("wrote", os.path.relpath(out, os.path.join(HERE, "..")))
    print("  description id=%s... (%d ops)" % (data["description"]["id_hex"][:16], len(data["description"]["operations"])))
    print("  directory A id=%s... fork@pos %d" % (
        data["directory"]["a"]["id_hex"][:16], data["directory"]["fork"]["first_differing_position"]))
    print("  import id=%s... foreign_id=%s..." % (
        data["import"]["id_hex"][:16], data["import"]["foreign_id_hex"][:16]))


if __name__ == "__main__":
    main()
