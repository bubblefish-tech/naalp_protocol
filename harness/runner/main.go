// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// naalp-conform — the N-AALP cross-language conformance runner.
//
// It drives the shared conformance corpus (assembled by tools/conformance_corpus.py from the
// per-family non-circular oracles) through ONE per-language SDK adapter, launched as a child
// process, over a length-prefixed JSON stdin/stdout pipe. Each adapter's answer is graded
// against the corpus's committed expected value (F3: expected values trace to an RFC/FIPS/NIST
// vector or a from-scratch constructor, never to another implementation). No adapter is ever
// compared to another here; cross-language agreement on the deterministic ML-DSA signature is
// the separate crypto-consensus gate.
//
// Wire contract (byte-compatible with the N-PAMP harness this is modeled on):
//   - framing: 4-byte little-endian uint32 length N, then N bytes of UTF-8 JSON, both directions;
//     the adapter flushes stdout after every response.
//   - request:  {"op": "<op>", "in": { ...fields... }}
//   - response: exactly one of {"out": {...}} | {"error": "<reason>"} | {"skipped": "<why>"}
//   - all byte-valued fields are lowercase hex strings; 64-bit counters may be a JSON number or
//     a decimal string (adapters parse tolerantly).
//
// Grading per case, keyed off the case's "result":
//   - transport/call error  -> Fail
//   - response has "skipped" -> Unimplemented (does NOT fail CI; tracked)
//   - result "invalid"       -> Pass iff the adapter returned "error"; Fail if it returned "out"
//   - result "acceptable"    -> Pass (as long as the call itself succeeded)
//   - result "valid"         -> adapter must return "out" and every key in "expected" must match
// Exit code is 1 iff any case Failed, else 0.
//
// Usage:
//   naalp-conform run --testee "<launch command>" [--corpus <path>] [--junit <path>] [--timeout <sec>]
//   naalp-conform vectors            # dump the embedded corpus to stdout
package main

import (
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed corpus/corpus.json
var embeddedCorpus []byte

type Corpus struct {
	Algorithm     string      `json:"algorithm"`
	SchemaVersion int         `json:"schemaVersion"`
	SpecRevision  string      `json:"specRevision"`
	TestGroups    []TestGroup `json:"testGroups"`
}

type TestGroup struct {
	Op      string     `json:"op"`
	Profile string     `json:"profile"`
	Tests   []TestCase `json:"tests"`
}

type TestCase struct {
	TcID        int                    `json:"tcId"`
	Requirement string                 `json:"requirement"`
	Comment     string                 `json:"comment"`
	In          map[string]interface{} `json:"in"`
	Expected    map[string]interface{} `json:"expected"`
	Result      string                 `json:"result"`
	Flags       []string               `json:"flags"`
}

type Request struct {
	Op string                 `json:"op"`
	In map[string]interface{} `json:"in"`
}

type Response struct {
	Out     map[string]interface{} `json:"out,omitempty"`
	Error   string                 `json:"error,omitempty"`
	Skipped string                 `json:"skipped,omitempty"`
}

// ---- testee subprocess ----

type Testee struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out io.Reader
}

// splitCommand splits a command string into argv, honoring single and double quotes so a
// launch command like `python harness/adapters/python/adapter.py` or a quoted spaced path
// is passed correctly.
func splitCommand(s string) []string {
	var args []string
	var cur strings.Builder
	quote := rune(0)
	inWord := false
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == ' ' || r == '\t':
			if inWord {
				args = append(args, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if inWord {
		args = append(args, cur.String())
	}
	return args
}

func startTestee(command string) (*Testee, error) {
	argv := splitCommand(command)
	if len(argv) == 0 {
		return nil, fmt.Errorf("empty --testee command")
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Testee{cmd: cmd, in: in, out: out}, nil
}

func (t *Testee) write(req Request) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	var lp [4]byte
	binary.LittleEndian.PutUint32(lp[:], uint32(len(b)))
	if _, err := t.in.Write(lp[:]); err != nil {
		return err
	}
	_, err = t.in.Write(b)
	return err
}

func (t *Testee) read() (Response, error) {
	var lp [4]byte
	if _, err := io.ReadFull(t.out, lp[:]); err != nil {
		return Response{}, err
	}
	n := binary.LittleEndian.Uint32(lp[:])
	body := make([]byte, n)
	if _, err := io.ReadFull(t.out, body); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.Unmarshal(body, &resp); err != nil {
		return Response{}, fmt.Errorf("bad response json: %w (%s)", err, string(body))
	}
	return resp, nil
}

// call sends one request and awaits the response under a timeout; a timeout returns an error and
// leaves the caller to abort (the process is killed by the caller on any transport failure).
func (t *Testee) call(req Request, timeout time.Duration) (Response, error) {
	type result struct {
		resp Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		if err := t.write(req); err != nil {
			ch <- result{err: err}
			return
		}
		resp, err := t.read()
		ch <- result{resp, err}
	}()
	select {
	case r := <-ch:
		return r.resp, r.err
	case <-time.After(timeout):
		return Response{}, fmt.Errorf("timeout after %s on op %q", timeout, req.Op)
	}
}

func (t *Testee) close() {
	t.in.Close()
	_ = t.cmd.Wait()
}

// ---- grading ----

type Outcome int

const (
	Pass Outcome = iota
	Fail
	Unimplemented
)

func (o Outcome) String() string {
	switch o {
	case Pass:
		return "pass"
	case Fail:
		return "FAIL"
	default:
		return "skip"
	}
}

func gradeCase(tc TestCase, resp Response, callErr error) (Outcome, string) {
	if callErr != nil {
		return Fail, "call error: " + callErr.Error()
	}
	if resp.Skipped != "" {
		return Unimplemented, "skipped: " + resp.Skipped
	}
	switch tc.Result {
	case "invalid":
		if resp.Error != "" {
			return Pass, "rejected: " + resp.Error
		}
		return Fail, "expected rejection, got out"
	case "acceptable":
		return Pass, "acceptable"
	default: // "valid"
		if resp.Error != "" {
			return Fail, "unexpected error: " + resp.Error
		}
		if resp.Out == nil {
			return Fail, "no out"
		}
		if ok, why := matchExpected(tc.Expected, resp.Out); !ok {
			return Fail, why
		}
		return Pass, "ok"
	}
}

// matchExpected checks every key present in expected against out (subset match; extra keys in out
// are ignored), comparing values with valEqual (case-insensitive strings, numeric, bool, arrays,
// nested maps).
func matchExpected(expected, out map[string]interface{}) (bool, string) {
	keys := make([]string, 0, len(expected))
	for k := range expected {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		got, present := out[k]
		if !present {
			return false, fmt.Sprintf("missing key %q", k)
		}
		if !valEqual(expected[k], got) {
			return false, fmt.Sprintf("key %q: expected %v, got %v", k, expected[k], got)
		}
	}
	return true, ""
}

func valEqual(a, b interface{}) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && strings.EqualFold(av, bv)
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case float64:
		return numEqual(av, b)
	case []interface{}:
		bv, ok := b.([]interface{})
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !valEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]interface{}:
		bv, ok := b.(map[string]interface{})
		if !ok {
			return false
		}
		ok2, _ := matchExpected(av, bv)
		return ok2 && len(av) == len(bv)
	case nil:
		return b == nil
	default:
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
}

// numEqual compares an expected number to a value that may be a JSON number or a decimal string
// (adapters are allowed to return 64-bit counters as strings).
func numEqual(a float64, b interface{}) bool {
	switch bv := b.(type) {
	case float64:
		return a == bv
	case string:
		f, err := strconv.ParseFloat(bv, 64)
		return err == nil && a == f
	default:
		return false
	}
}

// ---- run ----

type opResult struct {
	op       string
	pass     int
	fail     int
	skip     int
	failures []string
}

func loadCorpus(path string) (*Corpus, error) {
	raw := embeddedCorpus
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = b
	}
	var c Corpus
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func runConformance(command, corpusPath, junitPath string, timeout time.Duration) int {
	corpus, err := loadCorpus(corpusPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "corpus:", err)
		return 2
	}
	tt, err := startTestee(command)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start testee:", err)
		return 2
	}
	defer tt.close()

	var results []opResult
	totalPass, totalFail, totalSkip := 0, 0, 0
	aborted := false

	for _, g := range corpus.TestGroups {
		res := opResult{op: g.Op}
		for _, tc := range g.Tests {
			resp, callErr := tt.call(Request{Op: g.Op, In: tc.In}, timeout)
			outcome, msg := gradeCase(tc, resp, callErr)
			switch outcome {
			case Pass:
				res.pass++
				totalPass++
			case Unimplemented:
				res.skip++
				totalSkip++
			case Fail:
				res.fail++
				totalFail++
				res.failures = append(res.failures,
					fmt.Sprintf("%s tc%d (%s): %s", g.Op, tc.TcID, tc.Requirement, msg))
			}
			if callErr != nil { // a transport failure poisons the pipe; stop the run
				aborted = true
				break
			}
		}
		results = append(results, res)
		if aborted {
			break
		}
	}

	printSummary(command, corpus, results, totalPass, totalFail, totalSkip, aborted)
	if junitPath != "" {
		if err := writeJUnit(junitPath, command, results); err != nil {
			fmt.Fprintln(os.Stderr, "junit:", err)
		}
	}
	if totalFail > 0 || aborted {
		return 1
	}
	return 0
}

func printSummary(command string, c *Corpus, results []opResult, pass, fail, skip int, aborted bool) {
	fmt.Printf("\nN-AALP conformance — %s (%s)\n", c.Algorithm, c.SpecRevision)
	fmt.Printf("  testee: %s\n\n", command)
	fmt.Printf("  %-24s %6s %6s %6s\n", "op", "pass", "FAIL", "skip")
	fmt.Printf("  %-24s %6s %6s %6s\n", "------------------------", "----", "----", "----")
	for _, r := range results {
		fmt.Printf("  %-24s %6d %6d %6d\n", r.op, r.pass, r.fail, r.skip)
	}
	fmt.Printf("  %-24s %6d %6d %6d\n", "TOTAL", pass, fail, skip)
	if fail > 0 {
		fmt.Println("\nFAILURES:")
		for _, r := range results {
			for _, f := range r.failures {
				fmt.Println("  -", f)
			}
		}
	}
	if aborted {
		fmt.Println("\nRUN ABORTED (transport failure — the adapter died or desynced).")
	}
	if fail == 0 && !aborted {
		fmt.Printf("\nRESULT: PASS (%d graded, %d unimplemented/skipped)\n", pass, skip)
	} else {
		fmt.Printf("\nRESULT: FAIL (%d passed, %d failed, %d skipped)\n", pass, fail, skip)
	}
}

// ---- JUnit ----

func writeJUnit(path, command string, results []opResult) error {
	var b strings.Builder
	total, fails, skips := 0, 0, 0
	for _, r := range results {
		total += r.pass + r.fail + r.skip
		fails += r.fail
		skips += r.skip
	}
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	fmt.Fprintf(&b, `<testsuites name="naalp-conform" tests="%d" failures="%d" skipped="%d">`+"\n", total, fails, skips)
	fmt.Fprintf(&b, `  <testsuite name="%s" tests="%d" failures="%d" skipped="%d">`+"\n",
		xmlEscape(command), total, fails, skips)
	for _, r := range results {
		for i := 0; i < r.pass; i++ {
			fmt.Fprintf(&b, `    <testcase classname="%s" name="pass-%d"/>`+"\n", xmlEscape(r.op), i)
		}
		for i := 0; i < r.skip; i++ {
			fmt.Fprintf(&b, `    <testcase classname="%s" name="skip-%d"><skipped/></testcase>`+"\n", xmlEscape(r.op), i)
		}
		for _, f := range r.failures {
			fmt.Fprintf(&b, `    <testcase classname="%s" name="fail"><failure>%s</failure></testcase>`+"\n",
				xmlEscape(r.op), xmlEscape(f))
		}
	}
	b.WriteString("  </testsuite>\n</testsuites>\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// ---- CLI ----

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  naalp-conform run --testee \"<launch command>\" [--corpus <path>] [--junit <path>] [--timeout <sec>]")
	fmt.Fprintln(os.Stderr, "  naalp-conform vectors")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "vectors":
		os.Stdout.Write(embeddedCorpus)
		if len(embeddedCorpus) == 0 || embeddedCorpus[len(embeddedCorpus)-1] != '\n' {
			fmt.Println()
		}
		return
	case "run":
		var testee, corpusPath, junitPath string
		timeout := 30 * time.Second
		args := os.Args[2:]
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--testee":
				i++
				if i < len(args) {
					testee = args[i]
				}
			case "--corpus":
				i++
				if i < len(args) {
					corpusPath = args[i]
				}
			case "--junit":
				i++
				if i < len(args) {
					junitPath = args[i]
				}
			case "--timeout":
				i++
				if i < len(args) {
					if s, err := strconv.Atoi(args[i]); err == nil {
						timeout = time.Duration(s) * time.Second
					}
				}
			default:
				fmt.Fprintln(os.Stderr, "unknown arg:", args[i])
				usage()
				os.Exit(2)
			}
		}
		if testee == "" {
			fmt.Fprintln(os.Stderr, "--testee is required")
			usage()
			os.Exit(2)
		}
		os.Exit(runConformance(testee, corpusPath, junitPath, timeout))
	default:
		usage()
		os.Exit(2)
	}
}
