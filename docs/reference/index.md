<!-- Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0. -->

# API reference

Every N-AALP SDK carries inline documentation comments on its public surface, so a full API
reference can be generated for each language with its standard doc tool. Two references are
**published and hosted automatically** on every release; the rest generate with a single command
from the source that ships in the package.

## Hosted (automatic on publish)

| Language | Hosted reference | Mechanism |
|---|---|---|
| **Rust** | [docs.rs/naalp](https://docs.rs/naalp) | docs.rs builds rustdoc automatically when the crate is published |
| **Go** | [pkg.go.dev/…/impl/go](https://pkg.go.dev/github.com/bubblefish-tech/naalp_protocol/impl/go) | pkg.go.dev renders the package doc comments once the module is tagged |
| **Java** | Javadoc jar | the `maven-javadoc-plugin` attaches a `-javadoc.jar` to the Maven Central release (see `impl/java/pom.xml`) |

## Generate locally (doc comments already ship in every SDK)

| Language | Command (from the SDK directory) | Tool |
|---|---|---|
| Rust | `cargo doc --open` | rustdoc |
| Go | `go doc ./...`  (or browse pkg.go.dev) | go doc |
| Python | `pdoc naalp`  ·  or `sphinx-apidoc` | pdoc / Sphinx |
| TypeScript | `npx typedoc` | TypeDoc (`impl/typescript/typedoc.json`) |
| Java | `mvn javadoc:javadoc` | Javadoc |
| Kotlin | `./gradlew dokkaHtml` | Dokka |
| C# | `docfx`  ·  or the emitted XML doc (`GenerateDocumentationFile`) | DocFX |
| Ruby | `yard doc` | YARD (`impl/ruby/.yardopts`) |
| PHP | `phpdoc` | phpDocumentor |
| Swift | `swift package generate-documentation` | DocC (swift-docc-plugin) |

## Where the documentation lives in source

The reference content is the doc comments on each SDK's public types and functions — for example
Go doc comments, Rust `///` items, Python docstrings, TypeScript/JSDoc, Javadoc `/** */`, KDoc,
C# `/// <summary>`, YARD tags, PHPDoc, and Swift `///`. The high-level entry point in every SDK is
the object **envelope** (`Envelope` / `envelope`) — build → content-id-bind → sign → offline-verify
— plus the byte-level primitives (deterministic CBOR + content id, self-certifying identity, the
effect/authorization lattice, the spine record bodies, causal + federation ordering, the
twenty-channel registry).

For a task-oriented walkthrough rather than a symbol reference, start from each SDK's quickstart
under [Implementations](../implementations/index.md).

## Stability

All ten SDKs are versioned **0.1.0** and follow [Semantic Versioning](https://semver.org/). While
they are pre-1.0 (`0.y.z`), **the public API may change between minor versions** — `1.0.0` will
declare the API stable and, from then on, breaking changes require a major bump with a deprecation
notice. The **wire format is more stable than the SDK surface**: the object bytes are pinned by the
CDDL and the conformance corpus and are governed by the protocol's object major version (the `1` in
`N-AALP/1/…`), which changes far more conservatively than an SDK's minor version. See
[`CHANGELOG.md`](../../CHANGELOG.md) and the README "Versioning" section.
