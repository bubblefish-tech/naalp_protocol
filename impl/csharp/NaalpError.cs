// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;
using System.Collections.Generic;

namespace Naalp
{
    /// <summary>
    /// The N-AALP error object and the numeric error-code registry (design.md §3.5, R3.3/R3.4, T3.3).
    ///
    /// <para>The naalp-error object is the Control/Error body (channel 0x0000, kind 3, effect
    /// read_only) that carries one fail-closed rejection reason as
    /// {1:code, 2:name, ?3:detail, ?4:subject}. The registry is the ordered 129-entry name&lt;-&gt;code
    /// table below (<see cref="Names"/>; the code for Names[i] is i+1, 0 is reserved). Names is the
    /// single source the machine-readable registry (vectors/registry/error-codes.csv) and the CDDL
    /// naalp-error-code enum are generated to match, and scripts/registry_drift.py asserts the three
    /// agree; the table itself is graded against the non-circular oracle by the error.name_for_code
    /// conformance op.</para>
    ///
    /// <para>Two dual-carriage rules keep the code/name pair unambiguous and forward-compatible: a
    /// registered code whose name disagrees with the registry is rejected Malformed (the code is
    /// authoritative -- the strengthening direction); a code outside the registry is opaque and
    /// non-fatal (the name is diagnostic only), so a receiver interoperates with a peer emitting a
    /// later-registered code.</para>
    ///
    /// <para>Ported from impl/go/naalperror (with impl/rust/src/naalperror.rs as a byte-identical
    /// second reference); Names is copied verbatim from impl/go/naalperror/naalperror.go.</para>
    /// </summary>
    public static class NaalpError
    {
        /// <summary>Top of the RFC-Required standards range; codes &gt;= 0x8000 are private-use.</summary>
        public const long StandardsMax = 0x7FFF;

        /// <summary>
        /// The ordered error-code registry: the code for Names[i] is i+1 (0 is reserved and MUST NOT
        /// appear on the wire). Order is the fields-of-record authority for every code (§3.5).
        /// </summary>
        public static readonly string[] Names = new string[]
        {
            "NonCanonical", "DepthExceeded", "Malformed", "ContentIdMismatch", "HeaderBodyMismatch",
            "UnsupportedVersion", "UnknownCriticalExt", "UnknownKind", "RangeError", "NonNFC",
            "WrongAudience", "TooLarge", "TooManyCauses", "TooManyExtensions", "TooManyChunks",
            "UnknownAlg", "KeyAlgMismatch", "ProfileDowngrade", "HybridIncomplete", "SuiteMismatch",
            "CompositeRefused", "BadSignature", "SignerMismatch", "RotationUnauthorized", "KeyRevoked",
            "EffectNotAuthorized", "UnauthenticatedPrincipal", "MalformedSafetyLabel", "ApprovalRequired",
            "ApprovalMismatch", "ApprovalExpired", "AlreadyConsumed", "ConsumeFork", "ConsumeForkInvalid",
            "ConsumeReceiptUnsigned", "LedgerCorrupt", "LedgerUnsigned", "AudienceMismatch",
            "FreshnessSelfAsserted", "UnknownRefusalOutcome", "RefusalDetailLeak", "ChainBroken",
            "Equivocation", "CausalViolation", "ReceiptUnsigned", "ForkProofInvalid", "StageOutOfOrder",
            "StreamDigestMismatch", "StreamStateError", "ConfidentialTransportRequired", "PeerUnauthenticated",
            "NotDelivered", "MappingError", "EffectDeclarationMismatch", "StateTransitionError",
            "CapExceedsParent", "TransformCycle", "InputGateBypass", "TaskStateError", "ScopeOverlapConflict",
            "ReconcileMismatch", "WrongFlow", "SeqGap", "AboveCeiling", "GapDetected", "CommitMismatch",
            "ContMalformed", "GrantExpired", "GrantNotYetValid", "GrantRevoked", "UntrustedChainRoot",
            "DelegationDepthExceeded", "GrantMalformed", "NameMalformed", "NameChainBroken",
            "NameForkProofInvalid", "IllegalTransition", "TaskChainBroken", "ForeignCard", "DescMalformed",
            "MalformedApprovalFlag", "DirForkProofInvalid", "ImporterMismatch", "UnknownDescriptionFormat",
            "VerifierKeyMismatch", "NegMalformed", "UnknownRole", "UnknownProfile", "NotDescended",
            "NotOffer", "NotAccept", "MalformedCriticalFlag", "UnknownCriticalRisk", "ReferenceMismatch",
            "MalformedAnnotation", "EffectUnderDeclared", "EffectOutsideLattice", "ToolCallMalformed",
            "PayMalformed", "UnknownPaymentFormat", "GwMalformed", "UnknownGatewayDecision", "UIMalformed",
            "UIChainBroken", "UnknownUIEventKind", "ActionSubstituted", "UINoConsent", "StaleEpoch",
            "Unauthorized", "OwnerImmutable", "MemberExists", "MemberUnknown", "OwnerExists", "RoleInvalid",
            "RoomOpMismatch", "OpUnknown", "PrincipalUnknown", "PrincipalExists", "RebindUnauthorized",
            // Evidence-record family (E6.3 egress + S1 decision-record + S3 checkpoint + R1/R8), codes 120-129.
            "EgMalformed", "UnknownEgressBinding", "DecisionMalformed", "UnknownOrderingBasis", "OrderingDisclosureMalformed",
            "TermDispositionMalformed", "CheckpointMalformed", "WitnessRootMismatch", "InclusionProofInvalid", "ForeignProfileMalformed", "HazardMalformed", "HazardNotCovered", "HazardUnknown",
        };

        private static readonly Dictionary<string, long> CodeByName = BuildCodeByName();

        private static Dictionary<string, long> BuildCodeByName()
        {
            var m = new Dictionary<string, long>(Names.Length, StringComparer.Ordinal);
            for (int i = 0; i < Names.Length; i++)
            {
                m[Names[i]] = i + 1;
            }
            return m;
        }

        /// <summary>
        /// Returns the registered name for a code and whether the code is registered. A code of 0, or
        /// any value past the registered range, is unregistered (opaque per the open-registry rule).
        /// </summary>
        public static (string Name, bool Registered) NameForCode(long code)
        {
            if (code >= 1 && code <= Names.Length)
            {
                return (Names[code - 1], true);
            }
            return ("", false);
        }

        /// <summary>Returns the registered code for a name and whether the name is registered.</summary>
        public static (long Code, bool Registered) CodeForName(string name)
        {
            if (CodeByName.TryGetValue(name, out long c))
            {
                return (c, true);
            }
            return (0, false);
        }

        /// <summary>A decoded naalp-error body.</summary>
        public sealed class Object
        {
            public long Code;
            public string Name = "";
            public string Detail = ""; // "" if field 3 absent
            public byte[]? Subject; // null if field 4 absent
        }

        /// <summary>
        /// Returns the deterministic CBOR (RFC 8949 §4.2.1) of a naalp-error body
        /// {1:code, 2:name, ?3:detail, ?4:subject}. detail=="" omits field 3; subject==null omits
        /// field 4. The integer keys 1..4 are already in canonical ascending order.
        /// </summary>
        public static byte[] Encode(long code, string name, string detail, byte[]? subject)
        {
            var pairs = new List<Cbor.Pair>
            {
                new Cbor.Pair(new Cbor.U(1), new Cbor.U(code)),
                new Cbor.Pair(new Cbor.U(2), new Cbor.T(name)),
            };
            if (detail != "")
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(3), new Cbor.T(detail)));
            }
            if (subject != null)
            {
                pairs.Add(new Cbor.Pair(new Cbor.U(4), new Cbor.B(subject)));
            }
            return Cbor.Encode(new Cbor.M(pairs));
        }

        /// <summary>
        /// Parses a naalp-error body and enforces the dual-carriage rules. A structurally malformed
        /// body (not a map, a non-integer key, a wrong-typed or unknown field, or a missing code/name)
        /// is rejected Malformed. A registered code whose name disagrees with the registry is rejected
        /// Malformed (the code is authoritative). An unregistered code is accepted opaque (name
        /// diagnostic only).
        /// </summary>
        public static Object Decode(byte[] data)
        {
            Cbor.Value v;
            try
            {
                v = Cbor.Decode(data);
            }
            catch (Exception)
            {
                throw new NaalpException("Malformed", "naalp-error body is not well-formed deterministic CBOR");
            }
            if (!(v is Cbor.M m))
            {
                throw new NaalpException("Malformed", "naalp-error body is not a map");
            }

            long code = 0;
            string name = "";
            string detail = "";
            byte[]? subject = null;
            bool haveCode = false;
            bool haveName = false;

            foreach (Cbor.Pair p in m.Pairs)
            {
                if (!(p.K is Cbor.U k))
                {
                    throw new NaalpException("Malformed", "non-uint naalp-error key");
                }
                switch (k.V)
                {
                    case 1:
                        if (!(p.Val is Cbor.U cu))
                        {
                            throw new NaalpException("Malformed", "code not a uint");
                        }
                        code = cu.V;
                        haveCode = true;
                        break;
                    case 2:
                        if (!(p.Val is Cbor.T nt))
                        {
                            throw new NaalpException("Malformed", "name not a tstr");
                        }
                        name = nt.V;
                        haveName = true;
                        break;
                    case 3:
                        if (!(p.Val is Cbor.T dt))
                        {
                            throw new NaalpException("Malformed", "detail not a tstr");
                        }
                        detail = dt.V;
                        break;
                    case 4:
                        if (!(p.Val is Cbor.B sb))
                        {
                            throw new NaalpException("Malformed", "subject not a bstr");
                        }
                        subject = sb.V;
                        break;
                    default:
                        throw new NaalpException("Malformed", "unknown naalp-error field " + k.V); // closed grammar
                }
            }

            if (!haveCode || !haveName)
            {
                throw new NaalpException("Malformed", "naalp-error body missing code or name");
            }

            (string regName, bool registered) = NameForCode(code);
            if (registered && regName != name)
            {
                throw new NaalpException("Malformed", "registered code disagrees with the registry name"); // registered code + disagreeing name
            }

            return new Object { Code = code, Name = name, Detail = detail, Subject = subject };
        }
    }
}
