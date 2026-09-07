# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# C18 -- the signed description / directory primitive for the Ruby SDK (design.md §21; R-DESC-1..8).
#
# C18 is a signed, OFFLINE-VERIFIABLE description and discovery layer carried on N-AALP's own signed
# object. Its load-bearing property is that authority lives in the SIGNED BYTES, never in the connection
# or the host that served them: the same signed Description re-verifies byte-identically when an
# unrelated host serves it, because the signature (not a TLS-fetch origin) is the authority. It
# introduces NO new envelope, encoding, signature, identity, or audit mechanism (R-11.3): each object is
# an ordinary signed N-AALP body (COSE_Sign1, §4), reusing the closed C5 effect lattice (policy) and the
# T1 content-id framing (§2.3) unchanged.
#
# Three wire objects:
#
#   - Description {1: service, 2: operations[]} lists a service's operations, each Operation
#     {1: name, 2: effect, 3: requires_approval} carrying its C5 effect and an approval declaration.
#     parse_description reconstructs the whole operation table from the bytes ALONE.
#   - Directory {1: directory, 2: version, 3: members[]} is a signed collection whose members are
#     content ids. Two conflicting versions from ONE signer -- same directory and version, different
#     members -- are a FORK, detected at the FIRST-DIFFERING member POSITION (as the §8.5 audit
#     fork-proof reports the position of an equivocation).
#   - Import {1: importer, 2: format, 3: foreign, 4: operations[]} carries a foreign description format
#     (an A2A Agent Card, an ANP Agent Description, an AGNTCY Agent Badge) octet-for-octet (carriage,
#     not adoption) as a signed N-AALP attestation binding the foreign bytes' content id AND an N-AALP
#     effect mapping. The IMPORTER (the wrapping signer, recomputed self-certifyingly from the verifying
#     key) is the SOLE authorization identity; a foreign identity embedded in `foreign` never becomes an
#     N-AALP authorization identity -- the confused-deputy rule, enforced normatively here (R-14.6).
#
# Every check is fail-closed (§15). Ported from impl/go/description (cross-read against
# impl/python/naalp/description.py); the byte surface (bodies, heads, content ids, foreign-id binding,
# fork position, closed foreign-format rejection) is graded against vectors/description/cases.json; the
# offline-verification, fork-proof, and confused-deputy paths use real deterministic ML-DSA-65 and are
# demonstrated in isolation (the corpus carries no signed vector).
#
# Deviation from the Go reference, honest F4 note: Go's VerifyImport carries an ErrVerifierKeyMismatch
# guard because it takes BOTH an (alg, pubkey) pair AND a separate cose.Verifier `v`, and must bind them
# before deriving the authority id. The Ruby idiom (as Gateway.verify_decision / Delegation.
# verify_grant_object) verifies with a single (alg, pubkey) pair, so the authority id is ALWAYS derived
# from exactly the key that verified the signature -- the mismatch the Go guard prevents is structurally
# impossible here, so there is no VerifierKeyMismatch surface to port. It is not silently dropped; it is
# absent because the vulnerability it guards cannot arise in this signature.
require 'openssl'
require_relative 'cbor'
require_relative 'cose'
require_relative 'identity'
require_relative 'policy'

module Naalp
  module Description
    U = Naalp::CBOR::U
    N = Naalp::CBOR::N
    B = Naalp::CBOR::B
    T = Naalp::CBOR::T
    A = Naalp::CBOR::A
    M = Naalp::CBOR::M

    # The width of a head / content-id digest (SHA-384 = 48 bytes), matching the C7 audit chain.
    HEAD_SIZE = 48

    # Foreign description format codes (design §21; the closed naalp-description-format registry).
    FORMAT_A2A_CARD = 1          # A2A Agent Card
    FORMAT_ANP_DESCRIPTION = 2   # ANP Agent Description
    FORMAT_AGNTCY_BADGE = 3      # AGNTCY Agent Badge

    KNOWN_FORMATS = [FORMAT_A2A_CARD, FORMAT_ANP_DESCRIPTION, FORMAT_AGNTCY_BADGE].freeze

    # A named, fail-closed C18 error; #kind is the stable error kind (mirroring the Go/Rust kinds
    # DescMalformed, MalformedApprovalFlag, DirForkProofInvalid, ImporterMismatch,
    # UnknownDescriptionFormat, plus the reused cose kinds BadSignature/UnknownAlg/ProfileDowngrade/
    # KeyAlgMismatch).
    class DescriptionError < StandardError
      attr_reader :kind
      def initialize(kind, msg = "")
        super(msg.empty? ? kind : "#{kind}: #{msg}")
        @kind = kind
      end
    end

    module_function

    # SHA-384 over a body -- a 48-octet digest (the same construction as the C7 receipt head).
    def head(b)
      OpenSSL::Digest::SHA384.digest(b.dup.force_encoding(Encoding::BINARY))
    end

    # T1 framing multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body) (50 octets).
    def content_id(b)
      Naalp::CBOR.content_id(b.dup.force_encoding(Encoding::BINARY))
    end

    def known_format?(fmt)
      KNOWN_FORMATS.include?(fmt)
    end

    # ---- Operation: one listed operation with its effect + approval declaration (design §21.2) -----

    # One entry of a Description or Import mapping: a named operation, its C5 effect class, and whether
    # it requires an approval. requires_approval is the uint 1 (yes) / 0 (no) -- no CBOR boolean
    # (design §3.1).
    class Operation
      attr_reader :name, :effect, :requires_approval

      def initialize(name, effect, requires_approval)
        @name = name
        @effect = effect.to_i
        @requires_approval = requires_approval.to_i
      end

      def to_map
        M.new([[U.new(1), T.new(@name)], [U.new(2), U.new(@effect)], [U.new(3), U.new(@requires_approval)]])
      end

      # Deterministic-CBOR encoding of the operation body {1:name,2:effect,3:requires_approval}.
      def bytes
        Naalp::CBOR.encode(to_map)
      end

      # The per-operation effect, normalized fail-closed: an unrecognized value is destructive (R-6.2).
      def effect_class
        Naalp::Policy.normalize_effect(@effect)
      end

      # True iff the operation declares that it requires an approval.
      def requires_approval_flag
        @requires_approval == 1
      end
    end

    # Parse one operation map, rejecting a malformed shape (DescMalformed) or an approval flag outside
    # {0,1} (MalformedApprovalFlag). Fail-closed.
    def operation_from_value(v)
      raise DescriptionError.new("DescMalformed", "operation is not a map") unless v.is_a?(M)
      name = effect = req = nil
      v.pairs.each do |k, val|
        raise DescriptionError.new("DescMalformed", "non-uint operation key") unless k.is_a?(U)
        if k.v == 1 && val.is_a?(T)
          name = val.v
        elsif k.v == 2 && val.is_a?(U)
          effect = val.v
        elsif k.v == 3 && val.is_a?(U)
          req = val.v
        end
      end
      if name.nil? || effect.nil? || req.nil?
        raise DescriptionError.new("DescMalformed", "operation missing a mandatory field")
      end
      raise DescriptionError.new("MalformedApprovalFlag", "requires_approval is outside {0,1}") if req > 1
      Operation.new(name, effect, req)
    end

    def operations_from_value(v)
      raise DescriptionError.new("DescMalformed", "operations is not an array") unless v.is_a?(A)
      v.items.map { |e| operation_from_value(e) }
    end

    def operations_value(ops)
      A.new(ops.map(&:to_map))
    end

    def find_operation(ops, name)
      ops.each { |op| return [op, true] if op.name == name }
      [nil, false]
    end

    # ---- Description: a service's signed operation table (design §21.2) ----------------------------

    # A signed N-AALP object listing a service's operations. Its authority is in the signed bytes:
    # parse_description reconstructs the whole operation table (each operation's effect and approval
    # declaration) from the bytes alone, so an unrelated host serving the same bytes yields a
    # byte-identical verification (offline-verifiable, not fetch-authenticated).
    class Description
      attr_reader :service, :operations

      def initialize(service, operations)
        @service = service.dup.force_encoding(Encoding::BINARY)
        @operations = operations.to_a
      end

      # Deterministic-CBOR encoding {1: service, 2: operations[]}.
      def bytes
        Naalp::CBOR.encode(M.new([[U.new(1), B.new(@service)],
                                  [U.new(2), Naalp::Description.operations_value(@operations)]]))
      end

      def head
        Naalp::Description.head(bytes)
      end

      def id
        Naalp::Description.content_id(bytes)
      end

      # The named operation and whether it is listed.
      def operation(name)
        Naalp::Description.find_operation(@operations, name)
      end
    end

    # Reconstruct a Description from its body bytes ALONE -- the offline-verifiable property.
    def parse_description(b)
      m = decode_map(b)
      svc = bstr_field(m, 1)
      ops_v = field(m, 2)
      if svc.nil? || ops_v.nil?
        raise DescriptionError.new("DescMalformed", "description missing service or operations")
      end
      Description.new(svc, operations_from_value(ops_v))
    end

    # Produce the tagged COSE_Sign1 object over the Description body.
    def sign_description(d, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), d.bytes)
    end

    # Verify the Description's full signature under the profile, then reconstruct the operation table
    # from the signed body bytes. Because the authority is the signature over the bytes, this returns
    # the identical Description regardless of which host served `obj` (R-DESC-1). Fail-closed.
    def verify_description(obj, profile, alg, pubkey)
      parse_description(verify_sign1(obj, profile, alg, pubkey))
    end

    # ---- Directory: a signed collection of content ids, with fork detection (design §21.3) ----------

    # A signed collection object whose members are content ids. It carries a monotonic per-signer
    # version so two versions can be compared for equivocation.
    class Directory
      attr_reader :directory, :version, :members

      def initialize(directory, version, members)
        @directory = directory.dup.force_encoding(Encoding::BINARY)
        @version = version.to_i
        @members = members.map { |m| m.dup.force_encoding(Encoding::BINARY) }
      end

      # Deterministic-CBOR encoding {1: directory, 2: version, 3: members[]}.
      def bytes
        Naalp::CBOR.encode(M.new([
          [U.new(1), B.new(@directory)],
          [U.new(2), U.new(@version)],
          [U.new(3), A.new(@members.map { |m| B.new(m) })],
        ]))
      end

      def head
        Naalp::Description.head(bytes)
      end

      def id
        Naalp::Description.content_id(bytes)
      end
    end

    # Reconstruct a Directory from its body bytes alone.
    def parse_directory(b)
      m = decode_map(b)
      did = bstr_field(m, 1)
      ver = uint_field(m, 2)
      mem_v = field(m, 3)
      if did.nil? || ver.nil? || mem_v.nil? || !mem_v.is_a?(A)
        raise DescriptionError.new("DescMalformed", "directory missing or malformed field")
      end
      members = mem_v.items.map do |e|
        raise DescriptionError.new("DescMalformed", "member is not a bstr") unless e.is_a?(B)
        e.v
      end
      Directory.new(did, ver, members)
    end

    # Produce the tagged COSE_Sign1 object over the Directory body.
    def sign_directory(d, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), d.bytes)
    end

    # Verify the Directory's full signature under the profile, then reconstruct it from the signed body
    # bytes. Fail-closed.
    def verify_directory(obj, profile, alg, pubkey)
      parse_directory(verify_sign1(obj, profile, alg, pubkey))
    end

    # The first index at which two member lists differ, and whether they differ at all. If the lists
    # share a common prefix and one is longer, the difference is reported at the length of the shorter
    # list. Identical lists return [0, false].
    def first_member_difference(a, b)
      n = [a.length, b.length].min
      n.times do |i|
        return [i, true] if a[i].b != b[i].b
      end
      return [n, true] if a.length != b.length
      [0, false]
    end

    # Compare two directory versions from ONE signer and report whether they equivocate -- the SAME
    # directory id and version but DIFFERENT members -- and, if so, the FIRST-DIFFERING member POSITION.
    # A different directory id or version is a legitimate distinct object/succession, not a fork;
    # identical members are a benign duplicate. In both non-fork cases returns [0, false]. The caller
    # establishes the 'one signer' precondition by verifying both objects under the same key.
    def detect_fork(a, b)
      return [0, false] if a.directory.b != b.directory.b || a.version != b.version
      first_member_difference(a.members, b.members)
    end

    # Non-repudiable evidence of a directory fork: two validly-signed Directory objects by ONE signer at
    # the SAME (directory, version) listing DIFFERENT members, carried as the accused signer's OWN two
    # signed objects. Because a single verifier checks BOTH signed objects, the proof is self-contained.
    class DirectoryForkProof
      attr_reader :signer, :signed_a, :signed_b

      def initialize(signer, signed_a, signed_b)
        @signer = signer.dup.force_encoding(Encoding::BINARY)
        @signed_a = signed_a
        @signed_b = signed_b
      end

      # Check that this is a genuine directory fork by the signer whose key is (alg, pubkey), and return
      # the FIRST-DIFFERING member POSITION. Accepts iff ALL hold: (1) the signer id is present; (2)
      # BOTH signed objects verify under the key (which, because a single verifier checks both, proves
      # one signer); (3) the two directories share one directory id and version; and (4) their member
      # lists differ. Any failure rejects the whole proof (fail-closed): an unnamed signer, a different
      # directory/version, or identical members is DirForkProofInvalid; a signature that does not verify
      # propagates BadSignature.
      def verify(profile, alg, pubkey)
        raise DescriptionError.new("DirForkProofInvalid", "an unnamed accused is not evidence") if @signer.bytesize == 0
        a = Naalp::Description.verify_directory(@signed_a, profile, alg, pubkey)
        b = Naalp::Description.verify_directory(@signed_b, profile, alg, pubkey)
        pos, fork = Naalp::Description.detect_fork(a, b)
        unless fork
          raise DescriptionError.new("DirForkProofInvalid",
                                     "same directory+version identical members, or not the same versioned directory")
        end
        pos
      end
    end

    # ---- Import: foreign description carried as a signed attestation (design §21.4) -----------------

    # Carries a foreign description format octet-for-octet (carriage, not adoption) as a signed N-AALP
    # attestation. `importer` is the wrapping signer id (the sole authorization identity); `foreign` is
    # the foreign bytes verbatim; `operations` is the N-AALP effect mapping the importer attests. The
    # foreign bytes' content id is bound by foreign_id.
    class Import
      attr_reader :importer, :format, :foreign, :operations

      def initialize(importer, format, foreign, operations)
        @importer = importer.dup.force_encoding(Encoding::BINARY)
        @format = format.to_i
        @foreign = foreign.dup.force_encoding(Encoding::BINARY)
        @operations = operations.to_a
      end

      # Deterministic-CBOR encoding {1: importer, 2: format, 3: foreign, 4: operations[]}.
      def bytes
        Naalp::CBOR.encode(M.new([
          [U.new(1), B.new(@importer)],
          [U.new(2), U.new(@format)],
          [U.new(3), B.new(@foreign)],
          [U.new(4), Naalp::Description.operations_value(@operations)],
        ]))
      end

      def head
        Naalp::Description.head(bytes)
      end

      def id
        Naalp::Description.content_id(bytes)
      end

      # The T1 content id of the carried foreign bytes -- the hash the attestation binds. A changed
      # foreign document yields a different foreign_id, so an attestation binds the exact bytes.
      def foreign_id
        Naalp::Description.content_id(@foreign)
      end

      def operation(name)
        Naalp::Description.find_operation(@operations, name)
      end
    end

    # Reconstruct an Import from its body bytes alone. A format code outside the closed
    # naalp-description-format set {1,2,3} is rejected on decode (UnknownDescriptionFormat), never
    # carried as an unknown format. Fail-closed.
    def parse_import(b)
      m = decode_map(b)
      imp = bstr_field(m, 1)
      fmt = uint_field(m, 2)
      foreign = bstr_field(m, 3)
      ops_v = field(m, 4)
      if imp.nil? || fmt.nil? || foreign.nil? || ops_v.nil?
        raise DescriptionError.new("DescMalformed", "import missing a mandatory field")
      end
      unless known_format?(fmt)
        raise DescriptionError.new("UnknownDescriptionFormat",
                                   "import format #{fmt} is outside the closed set {1,2,3}")
      end
      Import.new(imp, fmt, foreign, operations_from_value(ops_v))
    end

    # Produce the tagged COSE_Sign1 object over the Import body.
    def sign_import(im, alg, seed)
      Naalp::COSE.cose_sign1(alg, seed, protected_header(alg), im.bytes)
    end

    # An Import that has passed signature verification and the confused-deputy check. authority_id is
    # the self-certifying signer id RECOMPUTED from the verifying key -- the wrapping signer, and the
    # only authorization identity. It is never any identity parsed from the foreign bytes.
    ResolvedImport = Struct.new(:authority_id, :format, :foreign_id, :operations)

    # Verify a foreign-description import end-to-end and enforce the confused-deputy rule normatively.
    # It (1) verifies the signed object under the profile with real crypto; (2) recomputes the wrapping
    # signer's SELF-CERTIFYING id from the verifying key (identity.signer_id); and (3) requires the
    # attestation's `importer` field to equal that recomputed id (ImporterMismatch otherwise). The
    # returned authority_id is that recomputed key id -- the wrapping signer -- so no field inside the
    # carried foreign bytes, including any foreign identity claim, can ever become the N-AALP
    # authorization identity (R-14.6). Any failure returns its named error and authorizes nothing.
    def verify_import(obj, profile, alg, pubkey)
      payload = verify_sign1(obj, profile, alg, pubkey)
      im = parse_import(payload)
      key_id = Naalp::Identity.signer_id(alg, pubkey)
      # The authorization identity is the wrapping key's own id. The attestation's declared importer
      # MUST match it: a signer can only ever import AS ITSELF, never as a foreign identity it names.
      unless im.importer.dup.force_encoding(Encoding::UTF_8) == key_id
        raise DescriptionError.new("ImporterMismatch", "the attested importer is not the verifying key's signer id")
      end
      ResolvedImport.new(key_id, im.format, im.foreign_id, im.operations)
    end

    # ---- signing / verification helpers (COSE_Sign1 with the bare {1: alg} header) ------------------

    # The bare {1: alg} COSE_Sign1 protected header (§4), as the reference cose.Sign1 emits (matching
    # Gateway.gateway_protected_header).
    def protected_header(alg)
      Naalp::CBOR.encode(M.new([[U.new(1), N.new(alg)]]))
    end

    # Verify a tagged COSE_Sign1 object under the profile floor with real crypto and return the payload.
    # Mirrors Gateway.verify_decision's checks: alg registry, profile floor, key-alg match, signature.
    # Fail-closed with a named DescriptionError.
    def verify_sign1(obj, profile, alg, pubkey)
      prot, payload, sig = Naalp::COSE.parse_sign1_raw(obj)
      halg = alg_from_protected(prot)
      level, known = Naalp::COSE.alg_level(halg)
      raise DescriptionError.new("UnknownAlg", "unregistered alg #{halg}") unless known
      if level < Naalp::COSE.profile_min_level(profile)
        raise DescriptionError.new("ProfileDowngrade", "signature level below the profile minimum")
      end
      raise DescriptionError.new("KeyAlgMismatch", "alg #{halg} does not match the verifier key alg #{alg}") if halg != alg
      tbs = Naalp::COSE.to_be_signed_raw(prot, payload)
      unless Naalp::COSE.cose_verify1_raw(halg, pubkey, tbs, sig)
        raise DescriptionError.new("BadSignature", "signature does not verify")
      end
      payload
    end

    def alg_from_protected(prot)
      v = Naalp::CBOR.decode(prot)
      if v.is_a?(M)
        v.pairs.each do |k, val|
          return val.v if k.is_a?(U) && k.v == 1 && (val.is_a?(N) || val.is_a?(U))
        end
      end
      raise DescriptionError.new("DescMalformed", "protected header has no alg")
    end

    # ---- small deterministic-CBOR field accessors -------------------------------------------------

    def decode_map(b)
      begin
        v = Naalp::CBOR.decode(b)
      rescue Naalp::CBOR::NonCanonical
        raise DescriptionError.new("DescMalformed", "body is not well-formed deterministic CBOR")
      end
      raise DescriptionError.new("DescMalformed", "body is not a map") unless v.is_a?(M)
      v
    end

    def field(m, k)
      m.pairs.each { |key, val| return val if key.is_a?(U) && key.v == k }
      nil
    end

    def bstr_field(m, k)
      v = field(m, k)
      v.is_a?(B) ? v.v : nil
    end

    def uint_field(m, k)
      v = field(m, k)
      v.is_a?(U) ? v.v : nil
    end
  end
end
