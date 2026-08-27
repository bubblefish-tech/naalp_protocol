---
name: Specification issue (normative)
about: An ambiguity, inconsistency, interoperability gap, or security concern in the object format or behavior
title: "[spec] "
labels: ["specification"]
---

**Draft revision**
Which revision does this concern? (e.g., `draft-bubblefish-naalp-00`)

**Section / table / code-point**
Point to the section, CDDL production, table, or code point involved
(e.g. the envelope map, a channel/kind, an effect value, a `protocol_id` range).

**Problem**
Describe the ambiguity, inconsistency, interoperability gap, or security concern.
If two implementers could read the text and build incompatible (or insecure)
things, explain how.

**Impact**
- [ ] Affects object-level interoperability (envelope, CBOR profile, content-id, signer-id)
- [ ] Affects a security property (identity, effect authorization, approval, audit, downgrade, replay)
- [ ] Affects a code-point assignment (channel / kind / effect / carriage protocol-id)
- [ ] Affects an IANA registration
- [ ] Other

**Suggested resolution (optional)**
Proposed text or change, if you have one.
