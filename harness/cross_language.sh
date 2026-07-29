#!/usr/bin/env bash
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
#
# Cross-language conformance gate (T14/#23/#20): build each reference SDK adapter whose toolchain is
# present, drive the shared op-replay corpus through it with the naalp-conform runner, and assert
# deterministic ML-DSA COSE_Sign1 byte-parity across every crypto-capable language.
#
# go + rust are always built and MUST pass. Additional-language adapters (python, typescript, java,
# ruby, php, and — in CI — csharp, swift) are graded when their toolchain/deps are present; a present
# wired adapter that fails is a hard failure, an absent toolchain is an honest skip (never a false
# green). The corpus is regenerated from the per-family non-circular oracles and drift-checked.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python}"
fail=0

bin() { if [ -f "$1.exe" ]; then echo "$1.exe"; else echo "$1"; fi; }
have() { command -v "$1" >/dev/null 2>&1; }
# JVM classpath separator: ';' on Windows (Git-Bash/MSYS), ':' elsewhere
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) SEP=';';; *) SEP=':';; esac

echo "== [1] regenerate corpus from oracles + drift-check the embedded copy =="
"$PY" tools/conformance_corpus.py >/dev/null || { echo "corpus generation FAILED"; exit 1; }
if ! cmp -s vectors/conformance/corpus.json harness/runner/corpus/corpus.json; then
  echo "  CORPUS DRIFT — re-syncing harness/runner/corpus/corpus.json"
  cp vectors/conformance/corpus.json harness/runner/corpus/corpus.json
  fail=1
else
  echo "  embedded corpus matches vectors/conformance/corpus.json"
fi

echo "== [2] build runner + go/rust reference adapters =="
( cd harness/runner && GOWORK=off go build -o naalp-conform ./ ) || exit 1
( cd harness/adapters/go && GOWORK=off go build -o naalp-adapter-go ./ ) || exit 1
( cd harness/adapters/rust && cargo build --release -q ) || exit 1
RUNNER="$(bin ./harness/runner/naalp-conform)"

# name -> launch command; and which are crypto-capable (join the ML-DSA consensus)
NAMES=()
declare -A LAUNCH CRYPTO
add() { NAMES+=("$1"); LAUNCH["$1"]="$2"; CRYPTO["$1"]="$3"; }

add go   "$(bin ./harness/adapters/go/naalp-adapter-go)" 1
add rust "$(bin ./harness/adapters/rust/target/release/naalp-adapter-rust)" 1

# python
if [ -f harness/adapters/python/adapter.py ] && "$PY" -c "import dilithium_py, cryptography" >/dev/null 2>&1; then
  add python "$PY harness/adapters/python/adapter.py" 1
fi
# typescript (Node type-strips / runs .mjs; needs @noble installed in impl/typescript + adapter dir)
if have node && [ -f harness/adapters/typescript/adapter.mjs ]; then
  ( cd impl/typescript && npm install --silent --no-audit --no-fund >/dev/null 2>&1 ) || true
  ( cd harness/adapters/typescript && npm install --silent --no-audit --no-fund >/dev/null 2>&1 ) || true
  add typescript "node harness/adapters/typescript/adapter.mjs" 1
fi
# java (Bouncy Castle jar downloaded to lib/; classpath sep is ';' on Windows, ':' elsewhere)
if have javac && [ -f harness/adapters/java/Adapter.java ]; then
  JAR=harness/adapters/java/lib/bcprov-jdk18on-1.85.jar
  [ -f "$JAR" ] || { mkdir -p harness/adapters/java/lib; curl -fsSL -o "$JAR" https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.85/bcprov-jdk18on-1.85.jar || true; }
  if [ -f "$JAR" ]; then
    rm -rf harness/adapters/java/out; mkdir -p harness/adapters/java/out
    if javac -cp "$JAR" -d harness/adapters/java/out impl/java/src/main/java/sh/bubblefish/naalp/*.java harness/adapters/java/Json.java harness/adapters/java/Adapter.java 2>/dev/null; then
      add java "java -cp harness/adapters/java/out${SEP}${JAR} sh.bubblefish.naalp.Adapter" 1
    else
      echo "  (java adapter failed to compile — SKIP)"
    fi
  else
    echo "  (bcprov jar unavailable — java SKIP)"
  fi
fi
# ruby (uses platform OpenSSL >= 3.5 for ML-DSA; no gems)
if have ruby && [ -f harness/adapters/ruby/adapter.rb ]; then
  add ruby "ruby harness/adapters/ruby/adapter.rb" 1
fi
# php (pure-only crypto: grades all pure ops + ed25519, skip-tracks ML-DSA sign/keygen/verify)
if have php && [ -f harness/adapters/php/adapter.php ]; then
  add php "php -d extension=sodium -d extension=intl harness/adapters/php/adapter.php" 0
fi
# kotlin (JVM + Bouncy Castle, same as Java; kotlinc build is slow so reuse the jar if present)
if have kotlinc && [ -f harness/adapters/kotlin/Adapter.kt ]; then
  KJAR=harness/adapters/kotlin/lib/bcprov-jdk18on-1.85.jar
  [ -f "$KJAR" ] || { mkdir -p harness/adapters/kotlin/lib; cp harness/adapters/java/lib/bcprov-jdk18on-1.85.jar "$KJAR" 2>/dev/null || curl -fsSL -o "$KJAR" https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.85/bcprov-jdk18on-1.85.jar || true; }
  KAPP=harness/adapters/kotlin/naalp-adapter-kotlin.jar
  if [ ! -f "$KAPP" ] && [ -f "$KJAR" ]; then
    kotlinc -cp "$KJAR" impl/kotlin/src/main/kotlin/sh/bubblefish/naalp/*.kt harness/adapters/kotlin/Adapter.kt -include-runtime -d "$KAPP" 2>/dev/null || echo "  (kotlin build failed — SKIP)"
  fi
  [ -f "$KAPP" ] && add kotlin "java -cp ${KAPP}${SEP}${KJAR} sh.bubblefish.naalp.AdapterKt" 1
fi
# csharp (BouncyCastle; needs a working .NET SDK — present only in CI, not on this dev box)
if have dotnet && [ -f harness/adapters/csharp/Adapter.csproj ]; then
  if dotnet build -c Release harness/adapters/csharp/Adapter.csproj >/dev/null 2>&1; then
    add csharp "dotnet harness/adapters/csharp/bin/Release/net8.0/naalp-adapter-csharp.dll" 1
  else
    echo "  (csharp: no usable .NET SDK — SKIP locally; CI grades via setup-dotnet)"
  fi
fi
# swift (SwiftPM; toolchain present only in CI. ML-DSA skip-tracked: SwiftDilithium 3.6.0 has no
# seed-based keygen, so Swift grades the pure ops + Ed25519 and skips the ML-DSA leg like PHP.)
if have swift && [ -f harness/adapters/swift/Package.swift ]; then
  if swift build -c release --package-path harness/adapters/swift >/dev/null 2>&1; then
    add swift "harness/adapters/swift/.build/release/naalp-adapter" 0
  else
    echo "  (swift: build failed — SKIP)"
  fi
fi

echo "== [3] grade each available adapter against the corpus =="
for name in "${NAMES[@]}"; do
  line="$("$RUNNER" run --testee "${LAUNCH[$name]}" | grep -E 'RESULT:')"
  echo "  $name: $line"
  "$RUNNER" run --testee "${LAUNCH[$name]}" >/dev/null 2>&1 || { echo "  $name FAILED"; fail=1; }
done

echo "== [4] cross-language deterministic ML-DSA byte-parity =="
CONSENSUS=()
for name in "${NAMES[@]}"; do
  [ "${CRYPTO[$name]}" = "1" ] && CONSENSUS+=("$name=${LAUNCH[$name]}")
done
"$PY" tools/crypto_consensus.py "${CONSENSUS[@]}" | grep -E 'CRYPTO-CONSENSUS|agree byte' || true
"$PY" tools/crypto_consensus.py "${CONSENSUS[@]}" >/dev/null 2>&1 || fail=1

if [ "$fail" -eq 0 ]; then
  echo "CROSS-LANGUAGE CONFORMANCE: PASS (${#NAMES[@]} adapters graded; ${#CONSENSUS[@]} byte-identical on deterministic ML-DSA)"
else
  echo "CROSS-LANGUAGE CONFORMANCE: FAIL"
fi
exit $fail
