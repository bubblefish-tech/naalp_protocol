// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
using System;

namespace Naalp
{
    /// <summary>
    /// A rejection with a machine-stable <see cref="Kind"/> (NonCanonical, UnknownAlg, NonNFC,
    /// CausalViolation, MappingError, UnknownTransport, UnknownKind, EffectDeclarationMismatch, ...).
    /// The adapter maps every thrown NaalpException to a {"error"} response; the Kind is the reason
    /// prefix, mirroring the Python/Java reference SDKs.
    /// </summary>
    public sealed class NaalpException : Exception
    {
        public string Kind { get; }

        public NaalpException(string kind, string message)
            : base(kind + ": " + message)
        {
            Kind = kind;
        }
    }
}
