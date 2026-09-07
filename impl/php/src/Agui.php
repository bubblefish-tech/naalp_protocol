<?php
// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
/**
 * N-AALP C21 NAALP-AGUI UI-consent binding for the PHP SDK (design.md §24; R-AGUI-1..6).
 *
 * NAALP-AGUI binds a human-in-the-loop approval, captured in a user-interface event stream (the AG-UI
 * tool-lifecycle events an agent shows a user), to the EXACT action bytes by content id, and
 * RECEIPT-CHAINS the shown events so the shown sequence is provable offline. It introduces NO new
 * envelope, encoding, signature, identity, or audit mechanism (R-11.3): a UI event is an ordinary signed
 * N-AALP body (COSE_Sign1, §4), and the surface reuses the C7 audit receipt-chain construction (§8.1)
 * unchanged — head = SHA-384(body), genesis prev = 48 zero bytes, a monotonic seq, the prior head
 * carried in `prev` so editing or omitting an event breaks the next event's linkage — and the §7
 * approval binding (Naalp\Approval) UNCHANGED.
 *
 *   - UIEvent {1: session, 2: kind, 3: action, 4: seq, 5: prev} is one shown tool-lifecycle event.
 *     `kind` is a closed set (shown / args-shown / approved / rejected); `action` is the T1 content id
 *     of the action bytes shown to the user at this step; the chain is receipt-chained by prev/seq.
 *
 * The load-bearing properties, graded against the shared corpus:
 *   - A UI approval verifies ONLY against the EXACT action shown. verifyConsent walks the shown chain,
 *     takes the action content id from the shown-and-approved event, and requires the action actually
 *     being executed to hash to THAT content id (ActionSubstituted otherwise) AND the human §7 approval
 *     to bind it (ApprovalMismatch otherwise). A substituted action has a different content id.
 *   - A removed/omitted shown-event is detected with its POSITION. walkShown enforces contiguity and
 *     raises UIChainBroken on a gap; detectHole reports the first-broken position.
 *
 * An independent transcription of impl/go/agui (cross-read against impl/python/naalp/agui.py), graded
 * against the shared vectors/agui/cases.json. The kind vocabulary, event bodies/heads/ids, action
 * content ids, the shown-chain walk, the hole position, and the wire-format rejections are
 * signature-independent and pure.
 *
 * CRYPTO SCOPE (PURE-ONLY): PHP has no deterministic ML-DSA (FIPS 204) signer, so the UI-event signature
 * the reference makes with ML-DSA-65 is demonstrated here with a real Ed25519 (RFC 8032) signature via
 * ext-sodium (signUIEvent / verifyUIEvent / verifyShownChain take an injected verify closure, as
 * Approval does). verifyUIEvent (Go impl/go/agui/agui.go:158) is the single-event verify path pairing
 * with signUIEvent + parseUIEvent; verifyShownChain composes the same per-event check across a whole
 * chain. The corpus-graded surfaces (bodies/heads/ids, the shown-chain heads, the AGUI verdicts) are all
 * signature-independent and pure.
 *
 * Every check is fail-closed (§15): a failing object is rejected whole, returns its named error, and
 * causes no state change.
 */

declare(strict_types=1);

namespace Naalp;

/**
 * A named, fail-closed AGUI error; $kind is a stable string mirroring the Go/Rust/Python error kinds
 * (UIMalformed, UIChainBroken, UnknownUIEventKind, ActionSubstituted, UINoConsent). The approval
 * binding, expiry, and signature errors are the EXISTING §7/§4 errors reused unchanged
 * (Naalp\ApprovalMismatch, Naalp\ApprovalExpired, Naalp\BadSignature).
 */
class AguiError extends \RuntimeException
{
    public string $kind;

    public function __construct(string $kind, string $msg = "")
    {
        $this->kind = $kind;
        parent::__construct($msg === "" ? $kind : "$kind: $msg");
    }
}

/**
 * One shown tool-lifecycle event in a UI session's event stream. It chains onto the prior event: `prev`
 * is the prior event's head (Agui::genesis() for seq 0). `action` is the content id of the exact action
 * bytes shown to the user at this step.
 */
final class UIEvent
{
    public string $session; // UI session id (ties the stream together)
    public int $kind;       // the event kind (closed set)
    public string $action;  // content id of the exact action bytes shown at this step
    public int $seq;        // monotonic per-session chain position; seq 0 is the genesis event
    public string $prev;    // the prior event's head (Agui::HEAD_SIZE bytes; genesis is zero)

    public function __construct(string $session, int $kind, string $action, int $seq, string $prev)
    {
        $this->session = $session;
        $this->kind = $kind;
        $this->action = $action;
        $this->seq = $seq;
        $this->prev = $prev;
    }

    /** Deterministic-CBOR encoding {1: session, 2: kind, 3: action, 4: seq, 5: prev}. */
    public function bytes(): string
    {
        return Cbor::encode(new M([
            [new U(1), new B($this->session)],
            [new U(2), new U($this->kind)],
            [new U(3), new B($this->action)],
            [new U(4), new U($this->seq)],
            [new U(5), new B($this->prev)],
        ]));
    }

    /** The chain head after this event: SHA-384 of the event body (48 octets). Because the body carries
     * prev, editing any event breaks the next event's linkage. */
    public function head(): string
    {
        return \hash('sha384', $this->bytes(), true);
    }

    /** The event's T1 content id (50 octets). */
    public function id(): string
    {
        return Cbor::contentId($this->bytes());
    }
}

/** One step of a walked shown chain: the chain position, the event kind, the action content id shown,
 * and the chain head after it. */
final class ShownEvent
{
    public int $seq;
    public int $kind;
    public string $action;
    public string $head;

    public function __construct(int $seq, int $kind, string $action, string $head)
    {
        $this->seq = $seq;
        $this->kind = $kind;
        $this->action = $action;
        $this->head = $head;
    }
}

final class Agui
{
    /** The width of a chain head / prev link (SHA-384 = 48 bytes), matching the C7 audit chain. */
    public const HEAD_SIZE = 48;

    // UI event kinds — the closed AG-UI tool-lifecycle set. A kind outside the set is rejected.
    public const KIND_SHOWN = 0;      // the action / tool call was shown (rendered) to the user
    public const KIND_ARGS_SHOWN = 1; // the arguments were shown to the user
    public const KIND_APPROVED = 2;   // the user approved the shown action
    public const KIND_REJECTED = 3;   // the user rejected the shown action

    private const KIND_NAMES = [
        self::KIND_SHOWN => "shown",
        self::KIND_ARGS_SHOWN => "args-shown",
        self::KIND_APPROVED => "approved",
        self::KIND_REJECTED => "rejected",
    ];

    /** Whether $code is one of the closed UI-event kinds. */
    public static function isKnownKind(int $code): bool
    {
        return \array_key_exists($code, self::KIND_NAMES);
    }

    /** The kind name, or "unknown". */
    public static function kindName(int $code): string
    {
        return self::KIND_NAMES[$code] ?? "unknown";
    }

    /** A fresh 48-octet zero prev — the empty-chain link (the C7 chain genesis). */
    public static function genesis(): string
    {
        return \str_repeat("\x00", self::HEAD_SIZE);
    }

    /** The T1 content id of arbitrary bytes — the content id of an ACTION a UI event names in field 3
     * and a human approval binds. multihash(0x20, SHA-384(body)) = 0x20 0x30 || SHA-384(body). */
    public static function contentId(string $b): string
    {
        return Cbor::contentId($b);
    }

    /**
     * Reconstruct a UIEvent from its body bytes alone. A non-canonical body, a non-map, a non-uint key,
     * a mistyped field, or an absent mandatory field {1,2,3,4,5} is UIMalformed. Fail-closed.
     */
    public static function parseUIEvent(string $b): UIEvent
    {
        try {
            $v = Cbor::decode($b);
        } catch (\Throwable $e) {
            throw new AguiError("UIMalformed", "ui-event body is not well-formed deterministic CBOR");
        }
        if (!($v instanceof M)) {
            throw new AguiError("UIMalformed", "ui-event body is not a map");
        }
        $sess = $kind = $action = $seq = $prev = null;
        foreach ($v->pairs as [$k, $val]) {
            if (!($k instanceof U)) {
                throw new AguiError("UIMalformed", "non-uint ui-event key");
            }
            if ($k->v === 1 && $val instanceof B) {
                $sess = $val->v;
            } elseif ($k->v === 2 && $val instanceof U) {
                $kind = $val->v;
            } elseif ($k->v === 3 && $val instanceof B) {
                $action = $val->v;
            } elseif ($k->v === 4 && $val instanceof U) {
                $seq = $val->v;
            } elseif ($k->v === 5 && $val instanceof B) {
                $prev = $val->v;
            } else {
                throw new AguiError("UIMalformed", "unknown or mistyped ui-event field " . $k->v);
            }
        }
        if ($sess === null || $kind === null || $action === null || $seq === null || $prev === null) {
            throw new AguiError("UIMalformed", "ui-event body missing a mandatory field");
        }
        return new UIEvent($sess, $kind, $action, $seq, $prev);
    }

    /**
     * Sign a UI event with a real deterministic Ed25519 key derived from a 32-byte seed (the pure-tier
     * stand-in for the reference's ML-DSA-65 signer). The signed input is the event body bytes DIRECTLY.
     */
    public static function signUIEvent(UIEvent $e, string $seed): string
    {
        return Cose::ed25519Sign($seed, $e->bytes());
    }

    /**
     * Verify ONE UI event's signature (Ed25519-demonstrated, via the injected $verify closure
     * `fn(string $msg, string $sig): bool` — signUIEvent's counterpart), reconstruct it from the
     * signed body bytes, and validate the kind against the closed set (UnknownUIEventKind). A
     * bad/foreign signature is BadSignature. Fail-closed. Mirrors the Go reference's VerifyUIEvent
     * (impl/go/agui/agui.go:158), which verifies a full COSE_Sign1 object under a profile; this
     * pure-tier port verifies the RAW Ed25519 signature signUIEvent produces directly over the event
     * body — the same convention verifyShownChain already applies per-step — so there is no COSE_Sign1
     * wrapper or profile floor to check here (documented deviation, F4).
     */
    public static function verifyUIEvent(string $obj, string $sig, callable $verify): UIEvent
    {
        if (!$verify($obj, $sig)) {
            throw new BadSignature("ui-event signature does not verify");
        }
        $e = self::parseUIEvent($obj);
        if (!self::isKnownKind($e->kind)) {
            throw new AguiError("UnknownUIEventKind", "ui-event kind is outside the closed set");
        }
        return $e;
    }

    /**
     * Verify a UI event chain offline: each event's signature (Ed25519-demonstrated, via the injected
     * $verify closure `fn(string $msg, string $sig): bool`) AND the same structural continuity as
     * walkShown. A bad/foreign signature is BadSignature; a broken link, seq gap, session change, or
     * unknown kind is UIChainBroken / UnknownUIEventKind. Detects any reorder, omission, or substitution
     * of a shown event (§8.1). Fail-closed.
     *
     * @param array<int,UIEvent> $events
     * @param array<int,string>  $sigs   parallel to $events; the Ed25519 signature over each event body
     * @return array<int,UIEvent>
     */
    public static function verifyShownChain(array $events, array $sigs, callable $verify): array
    {
        $h = self::genesis();
        $session = null;
        $out = [];
        foreach ($events as $i => $e) {
            if (!isset($sigs[$i]) || !$verify($e->bytes(), $sigs[$i])) {
                throw new BadSignature("ui-event signature does not verify");
            }
            if (!self::isKnownKind($e->kind)) {
                throw new AguiError("UnknownUIEventKind", "ui-event kind is outside the closed set");
            }
            if ($i === 0) {
                $session = $e->session;
            } elseif ($e->session !== $session) {
                throw new AguiError("UIChainBroken", "a chain is for exactly one session");
            }
            if ($e->seq !== $i || $e->prev !== $h) {
                throw new AguiError("UIChainBroken", "ui-event prev/seq does not chain to the previous event");
            }
            $h = $e->head();
            $out[] = $e;
        }
        return $out;
    }

    /**
     * Verify a UI event chain's structural continuity OFFLINE (no signatures) and return the ordered
     * shown events. Requires every event to name the SAME session, seq i to equal its index, each kind
     * to be in the closed set, and prev to link to the previous event's head (genesis for seq 0). A gap,
     * reorder, omitted event, or a session change is UIChainBroken; an unknown kind is
     * UnknownUIEventKind. Fail-closed.
     *
     * @param array<int,UIEvent> $events
     * @return array<int,ShownEvent>
     */
    public static function walkShown(array $events): array
    {
        $out = [];
        $h = self::genesis();
        $session = null;
        foreach ($events as $i => $e) {
            if ($i === 0) {
                $session = $e->session;
            } elseif ($e->session !== $session) {
                throw new AguiError("UIChainBroken", "a chain is for exactly one session");
            }
            if (!self::isKnownKind($e->kind)) {
                throw new AguiError("UnknownUIEventKind", "ui-event kind is outside the closed set");
            }
            if ($e->seq !== $i || $e->prev !== $h) {
                throw new AguiError("UIChainBroken", "ui-event prev/seq does not chain to the previous event");
            }
            $h = $e->head();
            $out[] = new ShownEvent($e->seq, $e->kind, $e->action, $h);
        }
        return $out;
    }

    /**
     * Report whether a presented (possibly gappy) event list breaks contiguity — a deleted/omitted
     * shown-event — and, if so, the FIRST-BROKEN POSITION: the index i where the i-th presented event's
     * seq is not i or its prev does not link to the previous event's head. A contiguous list returns
     * [0, false].
     *
     * @param array<int,UIEvent> $events
     * @return array{0:int,1:bool}
     */
    public static function detectHole(array $events): array
    {
        $h = self::genesis();
        foreach ($events as $i => $e) {
            if ($e->seq !== $i || $e->prev !== $h) {
                return [$i, true];
            }
            $h = $e->head();
        }
        return [0, false];
    }

    /**
     * The content id of the action shown-and-approved in a walked chain, and whether an approved event
     * is present. It is the content id a valid consent binds; a chain with no approved event has no
     * consent to bind.
     *
     * @param array<int,ShownEvent> $shown
     * @return array{0:?string,1:bool}
     */
    public static function approvedActionCid(array $shown): array
    {
        foreach ($shown as $ev) {
            if ($ev->kind === self::KIND_APPROVED) {
                return [$ev->action, true];
            }
        }
        return [null, false];
    }

    /**
     * Bind a human-in-the-loop approval to the EXACT action shown in a UI event stream. It (1) walks the
     * shown chain, rejecting any gap/reorder/omission (UIChainBroken); (2) takes the action content id
     * from the shown-and-approved event (UINoConsent if there is none); (3) verifies the human §7
     * approval binds THAT shown content id and has not expired (ApprovalMismatch / ApprovalExpired /
     * BadSignature, from Naalp\Approval); and (4) requires the action actually being executed
     * ($actionBytes) to hash to the shown-and-approved content id — a SUBSTITUTED action has a different
     * content id and is rejected (ActionSubstituted). Every failure returns its named error and
     * authorizes nothing (fail-closed). On success the caller may execute exactly $actionBytes.
     *
     * $approverVerify is `fn(string $msg, string $sig): bool` — the injected human-approval signature
     * verifier (Ed25519 on the pure PHP port).
     *
     * @param array<int,UIEvent> $chain
     */
    public static function verifyConsent(array $chain, string $actionBytes, ApprovalRecord $appr, callable $approverVerify, string $apprSig, int $now): void
    {
        $shown = self::walkShown($chain); // UIChainBroken / UnknownUIEventKind on a hole
        [$shownCid, $ok] = self::approvedActionCid($shown);
        if (!$ok) {
            throw new AguiError("UINoConsent", "the shown chain carries no approved event — there is no human consent to bind");
        }
        // The human approval must be a valid signature binding the shown-and-approved action content id.
        Approval::verifyApproval($appr, $approverVerify, $apprSig, $shownCid, $now); // BadSignature / ApprovalMismatch / ApprovalExpired
        // The action actually being executed MUST be the exact one shown and approved: a substitution has
        // a different content id and is rejected. This is the seam a lax UI profile would drop.
        if (self::contentId($actionBytes) !== $shownCid) {
            throw new AguiError("ActionSubstituted", "the action being executed is not the exact action shown and approved in the UI stream");
        }
    }
}
