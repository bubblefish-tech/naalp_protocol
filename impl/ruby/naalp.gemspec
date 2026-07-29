# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
Gem::Specification.new do |spec|
  spec.name        = "naalp"
  spec.version     = "0.1.0"
  spec.license     = "Apache-2.0"
  spec.summary     = "Reference SDK for N-AALP (Native Agentic Application Layer Protocol), " \
                     "draft-bubblefish-naalp-00"
  spec.description = <<~DESC
    The Ruby reference implementation of N-AALP (draft-bubblefish-naalp-00): every message is a
    deterministically-encoded CBOR structure signed with COSE that carries, under one signature,
    its content identity, its signer, a closed effect label, optional approval/audit bindings, and
    its causal derivation — verifiable offline, over any transport. Post-quantum signatures use the
    platform OpenSSL (>= 3.5) deterministic ML-DSA-65/-87 (FIPS 204, rnd=0). The full object
    envelope, the CBOR/content-id/identity/effect/record/graph/channel primitives, and the byte
    output are graded byte-for-byte against the shared cross-language conformance corpus.
  DESC

  spec.authors  = ["Shawn Sammartano"]
  spec.email    = ["naalp-editor@bubblefish.sh"]
  spec.homepage = "https://github.com/bubblefish-tech/naalp_protocol"

  spec.required_ruby_version = ">= 3.1"

  spec.files        = Dir["lib/**/*.rb"] + ["QUICKSTART.md"]
  spec.require_paths = ["lib"]

  spec.metadata = {
    "source_code_uri"       => "https://github.com/bubblefish-tech/naalp_protocol",
    "documentation_uri"     => "https://datatracker.ietf.org/doc/draft-bubblefish-naalp-00/",
    "rubygems_mfa_required" => "true",
  }
end
