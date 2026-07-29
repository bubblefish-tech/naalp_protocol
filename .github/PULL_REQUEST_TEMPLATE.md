# Pull request

**What does this change?**
A one-line summary.

**Type of change**
- [ ] Editorial (wording, formatting, examples): no change to object behavior
- [ ] Normative (changes what a conforming implementation must do)
- [ ] Implementation (a reference SDK / adapter / oracle / harness change)

**If normative, confirm object-stability intent**
- [ ] This change does NOT alter the object envelope geometry, the deterministic
      CBOR profile, the content-id / signer-id construction, the effect set, the
      channel/kind number space, or the carriage `protocol_id` ranges (i.e. it
      stays within the frozen draft-00 wire), OR
- [ ] This change intentionally proposes a wire-breaking revision, and says so
      explicitly (with the new draft revision it targets).

**Conformance**
- [ ] `bash harness/run.sh` is green (two-implementation byte parity + CDDL +
      registry drift + cross-language), or the PR explains why not.
- [ ] Any new expected value comes from an independent, non-circular oracle
      (tools/), never from an implementation under test.

**Author-tool checks (for a draft change)**
- [ ] The draft renders with kramdown-rfc + xml2rfc without errors.
- [ ] `idnits` reports 0 errors and 0 flaws (author-tools.ietf.org).
- [ ] The source remains ASCII-safe.

**Related issue**
Closes #...

**Licensing**
- [ ] I agree my contribution is provided under Apache-2.0 (repo content) and,
      for the draft/RFC text, under the IETF Trust's Legal Provisions (BCP 78),
      consistent with `ipr: trust200902`.
