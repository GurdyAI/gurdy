// gurdy-proxy: transparent MCP interceptor, monitor mode (§5.1, ADR-3).
// Governance loop per call: identify → classify → decide → attest (§4.2),
// with hot-reloadable policy bundles (FR-10) and a localhost admin API.
// Never blocks traffic.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/GurdyAI/gurdy/proxy/internal/bundle"
	"github.com/GurdyAI/gurdy/proxy/internal/clock"
	"github.com/GurdyAI/gurdy/proxy/internal/extract"
	"github.com/GurdyAI/gurdy/proxy/internal/ledger"
	"github.com/GurdyAI/gurdy/proxy/internal/mcp"
	"github.com/GurdyAI/gurdy/proxy/internal/policy"
	"github.com/GurdyAI/gurdy/proxy/internal/tis"
	"github.com/GurdyAI/gurdy/proxy/internal/toolsig"
	"github.com/GurdyAI/gurdy/proxy/internal/version"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TxnHeader carries an SDK-minted transaction token (wire contract, ADR-9).
const TxnHeader = "Gurdy-Txn"

// tracer resolves through the global provider: a no-op unless main configures
// OTLP export (NFR-6). Decision spans join the agent's own trace via the
// propagated W3C traceparent (NFR-8).
var tracer = otel.Tracer("gurdy-proxy")

func main() {
	listen := flag.String("listen", ":8090", "listen address")
	upstream := flag.String("upstream", "", "upstream MCP server base URL (required)")
	policyFile := flag.String("policy", "", "Cedar policy file (default: embedded starter policies)")
	deployID := flag.String("deploy-id", "gurdy-local", "deployment ID (call-assertion audience)")
	tenant := flag.String("tenant", "local", "tenant ID (ledger partition key, with the workload — ADR-6)")
	ledgerDir := flag.String("ledger-dir", "gurdy-ledger", "decision ledger directory (this is the export — no secrets go here)")
	stateDir := flag.String("state-dir", "gurdy-state", "private key directory (deployment identity + ledger signing key)")
	adminAddr := flag.String("admin", "127.0.0.1:8091", "admin API address (localhost only by default)")
	otlpEndpoint := flag.String("otlp", "", "OTLP/HTTP trace endpoint (default $OTEL_EXPORTER_OTLP_ENDPOINT; empty = no export)")
	mintSock := flag.String("tis-socket", "",
		"sideband TIS socket for SDK mint/derive (default <state-dir>/tis.sock; \"off\" disables)")
	stdio := flag.Bool("stdio", false, "shim mode: wrap an MCP stdio server — gurdy-proxy -stdio [flags] <cmd> [args...]")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("gurdy-proxy"))
		return
	}

	var target *url.URL
	if *stdio {
		if flag.NArg() == 0 {
			log.Fatal("-stdio requires the MCP server command: gurdy-proxy -stdio [flags] <cmd> [args...]")
		}
	} else {
		var err error
		target, err = url.Parse(*upstream)
		if err != nil || target.Host == "" {
			log.Fatal("-upstream must be a valid URL, e.g. http://localhost:3000")
		}
	}

	eval, err := loadBundle(*policyFile)
	if err != nil {
		log.Fatalf("load policy: %v", err)
	}
	store := policy.NewStore(eval)
	// Both keys persist under -state-dir, deliberately outside -ledger-dir:
	// the ledger dir is what you hand an auditor (§8.5), so it must contain
	// no private key material. Restart-stable keys are what let tokens and
	// chains survive a bounce and replicas verify each other (D2, §5.2).
	identity, err := tis.New(*deployID, filepath.Join(*stateDir, "tis-key.pem"))
	if err != nil {
		log.Fatalf("init TIS: %v", err)
	}
	// The chain records what it is evidence of, inside the signature (§5.5
	// v0.8.5): tenant and instance come from here, workload from the partition
	// key. The instance id is the same nonce that binds call assertions, so a
	// record and an assertion can be traced to one process.
	led, err := ledger.Open(*ledgerDir, filepath.Join(*stateDir, "ledger-key.pem"),
		ledger.Identity{Tenant: *tenant, Instance: identity.Instance(),
			Producer: version.Producer()})
	if err != nil {
		log.Fatalf("open ledger: %v", err)
	}

	// The sideband mint API is how an SDK obtains a transaction credential at
	// task start (§5.9, D1) — a Unix socket in every mode, because the SDK is
	// local to the proxy in every topology that has one.
	stopMint := func() {}
	if *mintSock != "off" {
		path := *mintSock
		if path == "" {
			path = filepath.Join(*stateDir, "tis.sock")
		}
		l, err := listenMint(path)
		if err != nil {
			log.Fatalf("tis socket: %v", err)
		}
		// Timeouts: the body cap only applies once a handler runs, so a client
		// that opens a connection and dawdles over its headers would otherwise
		// hold a goroutine and an fd indefinitely.
		srv := &http.Server{
			Handler:           mintMux(identity, store),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       15 * time.Second,
			IdleTimeout:       60 * time.Second,
			MaxHeaderBytes:    16 << 10,
		}
		go func() {
			if err := srv.Serve(l); err != http.ErrServerClosed {
				log.Printf("tis socket: %v", err)
			}
		}()
		// No explicit unlink: Go's UnixListener removes the socket it created
		// on Close. Removing by path afterwards would race a *restarting*
		// proxy — the new process binds, the old one unlinks its socket, and
		// the SDK is left dialing a path nothing is listening on.
		stopMint = func() { srv.Close() }
		log.Printf("gurdy-proxy: TIS mint socket at %s (owner-only)", path)
	}

	// OTel export is opt-in (NFR-6: zero mandatory egress). Without an
	// endpoint the global tracer stays a no-op — spans cost nothing.
	// otelShutdown must run before any exit path so queued spans flush.
	otelShutdown := func() {}
	if *otlpEndpoint != "" {
		os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", *otlpEndpoint)
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		exp, err := otlptracehttp.New(context.Background())
		if err != nil {
			log.Fatalf("otlp exporter: %v", err)
		}
		tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
		otel.SetTracerProvider(tp)
		otelShutdown = func() { tp.Shutdown(context.Background()) }
	}

	if *stdio {
		// stdout is the MCP protocol channel; decisions go to stderr.
		g := newGateway(store, identity, led, *tenant,
			slog.New(slog.NewJSONHandler(os.Stderr, nil)))
		shimErr := runShim(g, flag.Args(), os.Stdin, os.Stdout)
		stopMint()
		if err := led.Close(); err != nil {
			log.Printf("ledger close: %v", err)
		}
		otelShutdown()
		if shimErr != nil {
			log.Fatalf("shim: %v", shimErr)
		}
		return
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if _, err := reload(store, *policyFile); err != nil {
				log.Printf("SIGHUP reload failed, bundle unchanged: %v", err)
			} else {
				cur, _ := store.Versions()
				log.Printf("SIGHUP reload: bundle %q in force", cur)
			}
		}
	}()

	admin := &http.Server{Addr: *adminAddr, Handler: adminMux(store, led, *policyFile)}
	go func() {
		if err := admin.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("admin: %v", err)
		}
	}()

	// Buffered, because an unbuffered handler puts a write(2) on the hot path of
	// every decision and slog serialises them behind one mutex. At NFR-2's 1000
	// decisions/sec that measured a 28ms p99 against a 2ms baseline — the single
	// largest contributor to tail latency in the whole proxy, and entirely
	// invisible until gurdy-bench ran the composed path under load.
	//
	// Safe to buffer precisely because this log is *not* the evidence. The
	// ledger is: it has its own writer, its own durability and its own coverage
	// records for what it loses. This stream is operator convenience, so trading
	// a few hundred milliseconds of it on a hard kill for a tenth of the tail
	// latency is the right way round. Flushed on the ticker and again at
	// shutdown, before the ledger closes.
	decisionOut := newFlushWriter(os.Stdout, 200*time.Millisecond)
	defer decisionOut.Close()

	srv := &http.Server{Addr: *listen, Handler: Handler(target, store, identity, led, *tenant,
		slog.New(slog.NewJSONHandler(decisionOut, nil)))}
	go func() {
		log.Printf("gurdy-proxy: monitor mode, %s -> %s, bundle %q, deploy %q, tenant %q, ledger %s, admin %s",
			*listen, target, eval.Version, *deployID, *tenant, *ledgerDir, *adminAddr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-stop
	stopMint()
	admin.Close()
	// Shutdown, not Close: it waits for in-flight handlers, so the records they
	// are still writing reach the export instead of becoming post-close drops
	// that only ever show up as a counter (§7). Hijacked connections are never
	// waited for by either, so the grace period is bounded and the coverage
	// counters below remain the backstop.
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.Shutdown(shutCtx); err != nil {
		srv.Close() // deadline hit: stop waiting, the gap gets counted
	}
	cancel()
	if err := led.Close(); err != nil { // final batch signature (§5.5)
		log.Printf("ledger close: %v", err)
	}
	// The export carries these as coverage records too (§5.5); the log line is
	// for the operator who never opens the export.
	if d, w, i := led.Dropped.Load(), led.WriteErrors.Load(), led.IdentityFail.Load(); d+w+i > 0 {
		log.Printf("WARNING: coverage gaps this run — %d records dropped, %d write errors, %d identity failures", d, w, i)
	}
	otelShutdown()
}

// loadBundle loads a policy bundle from path, or the embedded starter set
// when path is empty.
func loadBundle(path string) (*policy.Evaluator, error) {
	if path == "" {
		return policy.Load("starter-embedded", policy.Starter)
	}
	return bundle.Load(path)
}

// reload loads path and swaps it in; on any error the bundle in force is
// untouched (keep-last-good, FR-10).
func reload(store *policy.Store, path string) (*policy.Evaluator, error) {
	if path == "" {
		return nil, fmt.Errorf("no -policy path configured; embedded starter bundle cannot be reloaded")
	}
	ev, err := bundle.Load(path)
	if err != nil {
		return nil, err
	}
	store.Swap(ev)
	return ev, nil
}

// adminMux is the localhost admin API (§5.1; HTTP+JSON rather than gRPC —
// boring wins for a two-person team, revisit if a partner integration needs it).
func adminMux(store *policy.Store, led *ledger.Ledger, policyPath string) http.Handler {
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(v)
	}
	bundleState := func() map[string]any {
		cur, hist := store.Versions()
		return map[string]any{"bundle": cur, "history": hist}
	}
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		cur, _ := store.Versions()
		// Coverage findings belong here as well as in the export (§7): the
		// ledger is the evidence, /health is how an operator notices *today*
		// that the evidence is incomplete. "degraded" never means traffic
		// stopped — monitor mode always forwards (ADR-3) — it means this run
		// recorded less than it saw.
		dropped, writeErrors, identityFail := led.Dropped.Load(), led.WriteErrors.Load(), led.IdentityFail.Load()
		status := "ok"
		if dropped+writeErrors+identityFail > 0 {
			status = "degraded"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status": status, "bundle": cur,
			"coverage": map[string]any{
				"dropped": dropped, "write_errors": writeErrors, "identity_failed": identityFail,
			},
		})
	})
	// GET /latency — the live clocking surface (internal/clock). Per stage of
	// the governance loop, percentiles rather than averages, and carrying its own
	// statement of what it does not measure: the hop is the larger term of
	// NFR-1's budget and none of it appears here, so a reader who takes these as
	// the gate figure has been misled by us.
	//
	// On the admin API rather than the traffic port, and read-only, for the same
	// reason as /health: it is operator information, and the governed agent is a
	// process on the same box (§7).
	mux.HandleFunc("GET /latency", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, clock.Snapshots())
	})
	// DELETE /latency — start a fresh window. An operator watching a change land
	// wants the distribution since the change, not since boot.
	mux.HandleFunc("DELETE /latency", func(w http.ResponseWriter, r *http.Request) {
		clock.Reset()
		writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
	})

	mux.HandleFunc("GET /policy", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, bundleState())
	})
	mux.HandleFunc("POST /policy/reload", func(w http.ResponseWriter, r *http.Request) {
		if _, err := reload(store, policyPath); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error(), "bundle_unchanged": true})
			return
		}
		writeJSON(w, http.StatusOK, bundleState())
	})
	// Retention (D14). **Operator-invoked only, by author decision** — there is
	// no timer, no max-age setting, and no background sweep, because an
	// evidence product that deletes its own records on a schedule is a
	// different proposition from one that does it when asked. The signed
	// retention record makes either auditable; only one of them is defensible
	// without a human in the loop.
	//
	// It lives on the admin API rather than in a separate binary because the
	// running proxy is the only thing that can do it safely: it holds the
	// signing key, the open chain, and the writer goroutine the append has to
	// be serialized against. It inherits the localhost bind and the CSRF guard.
	//
	// Note for §7's threat model: this widens the admin-API surface from
	// "disarm the proxy" to "disarm it and remove evidence". That is already a
	// listed known-unmitigated item, and it is not made worse in kind — an
	// attacker who can POST here can also stop the process — but it is worse in
	// degree, and SECURITY.md says so rather than leaving it to be discovered.
	mux.HandleFunc("POST /retention/prune", func(w http.ResponseWriter, r *http.Request) {
		keep := 8
		if v := r.URL.Query().Get("keep"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error": "keep must be a positive integer (segments to retain per partition)"})
				return
			}
			keep = n
		}
		removed, err := led.Prune(keep)
		if err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"keep": keep, "pruned": removed})
	})
	mux.HandleFunc("POST /policy/rollback", func(w http.ResponseWriter, r *http.Request) {
		if _, err := store.Rollback(); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, bundleState())
	})
	return csrfGuard(mux)
}

// csrfGuard blocks browser-originated requests to the localhost admin API:
// cross-site form POSTs carry a foreign Origin, DNS-rebinding carries a
// foreign Host. CLI/curl traffic carries neither. Bearer-token auth comes
// with the team tier's non-localhost admin surface.
func csrfGuard(next http.Handler) http.Handler {
	localhost := func(hostport string) bool {
		host := hostport
		if h, _, err := net.SplitHostPort(hostport); err == nil {
			host = h
		}
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			if u, err := url.Parse(o); err != nil || !localhost(u.Host) {
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}
		}
		if !localhost(r.Host) {
			http.Error(w, "unexpected Host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// gateway wraps a reverse proxy with the governance loop (§4.2).
type gateway struct {
	rp *httputil.ReverseProxy
	// act is the Act stage of the loop (§4.2). Monitor mode in Phase 1; the
	// enforce actuator (ADR-14) is a second implementation, not a rewrite.
	act Actuator
	// upstream is where traffic actually goes. Extractors need the
	// *destination*, not the Host header the client sent to us: in every
	// topology but a bare demo those differ, and deriving "which provider
	// received this prompt" from the proxy's own hostname would answer a
	// question nobody asked.
	upstream *url.URL
	// sigs is what each upstream declared about its own tools, learned from
	// tools/list responses. Policy binds to (endpoint, signature) rather than to
	// a display name the agent chooses (§7).
	sigs      *toolsig.Registry
	store     *policy.Store
	tis       *tis.TIS
	led       *ledger.Ledger
	tenant    string
	decisions *slog.Logger

	mu      sync.RWMutex
	autoTxn map[string]autoTok // coarse principal -> auto-minted txn (§4.3)
}

// autoTok caches an auto-minted txn token beside the expiry we already knew
// when we minted it. Storing the expiry is what lets the hot path answer "is
// this still good?" with a clock comparison under a read lock, instead of an
// ES256 verify under an exclusive one (D12).
type autoTok struct {
	tok string
	exp time.Time
}

// autoRenew is how far before real expiry a cached token stops being handed
// out. It is not politeness about clock skew: if a token expires between the
// check here and DeriveCall a few microseconds later, the derive fails and the
// call is recorded with empty txn fields plus an identity gap (§5.5) — the
// evidence is degraded, not retried. DefaultTxnTTL is 15 minutes, so renewing
// one minute early costs a mint per principal per 14 minutes and removes the
// window entirely.
const autoRenew = time.Minute

// Handler builds the monitor-mode gateway. Every request is forwarded
// unmodified; inspection failure never drops traffic (NFR-3).
func Handler(target *url.URL, store *policy.Store, identity *tis.TIS, led *ledger.Ledger, tenant string, decisions *slog.Logger) http.Handler {
	g := newGateway(store, identity, led, tenant, decisions)
	g.rp = httputil.NewSingleHostReverseProxy(target)
	// http.DefaultTransport allows two idle connections per host. A sidecar
	// talks to exactly one upstream, so that is the entire pool: past two
	// concurrent calls every request dials a fresh TCP connection and leaves the
	// old one in TIME_WAIT. The p50 stays fine — a connection is usually free —
	// while the tail is dominated by connection setup, which at 1000 req/s
	// (NFR-2) measured a ~20ms p99 against a ~2ms baseline.
	//
	// Nothing in a microbenchmark can see this: it is entirely in the hop, which
	// is why §8.2 refuses to let NFR-1 be certified by summing standalone
	// numbers. Found by gurdy-bench on the first composed run.
	g.rp.Transport = &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          maxUpstreamConns,
		MaxIdleConnsPerHost:   maxUpstreamConns,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	g.upstream = target
	return g
}

// newGateway is the only way a gateway comes into being. The Act stage is not
// optional — a transport wired up without one would forward everything while
// looking like it had consulted a policy, which is the exact confusion the
// actuator interface exists to prevent — so it is set here rather than left to
// each call site to remember.
func newGateway(store *policy.Store, identity *tis.TIS, led *ledger.Ledger,
	tenant string, decisions *slog.Logger) *gateway {
	return &gateway{
		act:       monitorActuator{},
		sigs:      toolsig.New(),
		store:     store,
		tis:       identity,
		led:       led,
		tenant:    tenant,
		decisions: decisions,
		autoTxn:   map[string]autoTok{},
	}
}

// partition is the ledger chain key: per (tenant, workload) from v1, so
// per-partition sequential writes never serialize the fleet and adding
// tenancy later is not a chain migration (ADR-6).
//
// The workload is the *attested-coarse* principal, never the asserted one —
// an agent that varies its claimed principal must not be able to fragment or
// steer the chain its evidence lands on.
//
// Workload count is therefore driven by the environment, not by us: the
// ledger bounds open file descriptors itself (maxOpenParts). What remains
// unbounded is the in-memory partition map, which is the autoTxn ceiling
// (roadmap D6) and retires with the same idle-eviction fix.
func (g *gateway) partition(workload string) string {
	return g.tenant + "/" + workload
}

// destination is the host the request is being forwarded to. Falls back to the
// client's Host header only when there is no configured upstream, which is the
// stdio shim, where there is no HTTP hop at all.
func (g *gateway) destination(r *http.Request) string {
	if g.upstream != nil && g.upstream.Host != "" {
		return g.upstream.Host
	}
	return r.Host
}

// maxUpstreamConns is the idle-connection pool to the single upstream. Sized
// well above NFR-2's 1000 decisions/sec so the pool is never the constraint,
// and bounded so a pathological client cannot make the proxy exhaust its file
// descriptors — a monitor that runs out of fds stops governing (NFR-3).
const maxUpstreamConns = 256

// maxToolsListCapture bounds the one response body the proxy reads rather than
// only hashes. Generous for a real tool catalogue and small enough that a
// hostile upstream cannot make the proxy hold a large buffer per request.
const maxToolsListCapture = 1 << 20

// toSignatures adapts the wire shape to the registry's, so internal/toolsig
// does not import internal/mcp and the two can be tested apart.
func toSignatures(decls []mcp.ToolDeclaration) []toolsig.Declaration {
	out := make([]toolsig.Declaration, 0, len(decls))
	for _, d := range decls {
		out = append(out, toolsig.Declaration{
			Name: d.Name, Description: d.Description, InputSchema: d.InputSchema,
		})
	}
	return out
}

// maxInspect bounds how much body the proxy buffers for inspection; larger
// bodies are forwarded uninspected and logged indeterminate (§5.1) — monitor
// mode never breaks traffic, and never OOMs on it either.
const maxInspect = 4 << 20

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var calls []string // call_ids decided on this request, awaiting a response record
	var listing bool   // this request asks the upstream to enumerate its tools
	if r.Body != nil && r.Method == http.MethodPost {
		body, err := io.ReadAll(io.LimitReader(r.Body, maxInspect+1))
		if err != nil {
			http.Error(w, "read body", http.StatusBadGateway)
			return
		}
		if len(body) > maxInspect {
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
			calls = append(calls, g.indeterminate(r, "body exceeds inspection limit"))
		} else {
			r.Body = io.NopCloser(bytes.NewReader(body))
			listing = mcp.IsToolsList(body)
			tcs := mcp.ParseToolsCalls(body)
			for _, tc := range tcs {
				if tc.Name == "" {
					calls = append(calls, g.indeterminate(r, "undecodable tools/call params"))
					continue
				}
				c := extract.Call{
					Tool: tc.Name, Arguments: tc.Arguments,
					Host: g.destination(r), Path: r.URL.Path, Body: body,
				}
				// What the upstream declared about this tool, if it ever did.
				if sig, declared := g.sigs.Lookup(g.destination(r), tc.Name); declared {
					c.Signature = &extract.Signature{
						Hash: sig.Hash, PathArgs: sig.PathArgs, URLArgs: sig.URLArgs,
					}
				}
				calls = append(calls, g.decide(r, c, body))
			}
			if len(tcs) == 0 {
				// Not MCP. Hand the raw request to the registry: a model call
				// is governed traffic too (llm/completion, v0.8.4), and
				// anything no extractor claims is forwarded ungoverned, as
				// before — silence here is "not our business", not a gap.
				c := extract.Call{Host: g.destination(r), Path: r.URL.Path, Body: body}
				switch res, ok := extract.Default.Classify(c); {
				case ok && res.Undecodable:
					// Recognized endpoint, unreadable body: forwarded like all
					// other traffic, but recorded — silence here is what a
					// deliberately malformed payload is buying (§8.4).
					calls = append(calls, g.indeterminate(r, "undecodable "+res.Action+" request"))
				case ok:
					calls = append(calls, g.decide(r, c, body))
				}
			}
		}
	}
	// Gurdy-Txn is consumed here and must not reach the upstream tool server:
	// it is a live bearer credential for the whole transaction, and an upstream
	// that receives one can mint call assertions in the agent's name. Deleting
	// it does not touch the pass-through invariant, which is about the request
	// body and the upstream's own response (TestPassThroughByteIdentical).
	r.Header.Del(TxnHeader)
	// A tools/list is not itself governed traffic — no decision, no record — but
	// its *answer* is where the upstream declares what it offers, and those
	// declarations are what let policy bind to a signature instead of a display
	// name. So it needs the wrapper even though it produces no call.
	if len(calls) == 0 && !listing {
		g.rp.ServeHTTP(w, r)
		return
	}
	rw := &hashingWriter{ResponseWriter: w, h: sha256.New(), status: http.StatusOK}
	if listing {
		rw.capture, rw.captureCap = &bytes.Buffer{}, maxToolsListCapture
	}
	g.rp.ServeHTTP(rw, r)
	if rw.capture != nil {
		// The upstream just published what it offers. Recording it here is what
		// makes a later call to an *undeclared* tool visible as such.
		if decls := mcp.ParseToolDeclarations(rw.capture.Bytes()); len(decls) > 0 {
			g.sigs.Observe(g.destination(r), toSignatures(decls))
		}
	}
	g.recordResponse(coarsePrincipal(r), calls, rw)
}

// hashingWriter hashes the response on its way to the client (§4.3 step 6).
// Streaming, never buffering: an SSE or long-poll response must reach the
// caller unchanged and undelayed (NFR-3, byte-identical pass-through), so the
// hash is computed from the same bytes as they pass.
type hashingWriter struct {
	http.ResponseWriter
	h        hash.Hash
	n        int64
	status   int
	hijacked bool
	// capture is non-nil only for a tools/list response, whose *declarations*
	// the proxy needs in order to bind policy to a tool signature rather than a
	// display name (§7, internal/toolsig). Everything else still streams and is
	// only hashed — buffering every response would cost memory proportional to
	// the largest download and delay a stream, which monitor mode may not do.
	capture    *bytes.Buffer
	captureCap int
}

func (w *hashingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *hashingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	// Timed separately from the decision because it behaves differently: a
	// per-byte cost with no cap, where the decision is a fixed cost per call
	// (roadmap D13). The client is written to first, so this delays the next
	// chunk rather than the first byte.
	hashed := clock.Respond.Time()
	w.h.Write(b[:n]) // hash what was actually delivered, not what was offered
	if w.capture != nil && w.capture.Len() < w.captureCap {
		// Bounded: a server that answers tools/list with something enormous
		// gets its declarations truncated and therefore unparsed, which the
		// registry treats as "no declarations" rather than as a reason to grow.
		w.capture.Write(b[:min(n, w.captureCap-w.capture.Len())])
	}
	hashed()
	w.n += int64(n)
	return n, err
}

// Flush keeps streaming responses streaming: without it the wrapper hides the
// upstream's http.Flusher and an SSE stream would buffer until completion —
// altering traffic, which monitor mode may never do (ADR-3).
func (w *hashingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the real writer to http.ResponseController, so every
// capability this wrapper does not name explicitly still reaches the client.
func (w *hashingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Hijack passes protocol switches through. Without it a 101 upgrade
// (WebSocket, h2c) fails with "can't switch protocols using non-Hijacker
// ResponseWriter" and the proxy answers 502 — inspection wiring breaking the
// traffic it exists to watch (NFR-3). Past the hijack the bytes leave through
// the raw connection, so nothing downstream can be hashed: the flag stops the
// response record from reporting a whole tunnel as zero bytes.
func (w *hashingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	c, rw, err := hj.Hijack()
	if err == nil {
		w.hijacked = true
	}
	return c, rw, err
}

// recordResponse closes out every call decided on this request. A JSON-RPC
// batch shares one response envelope, so its calls share one resp_hash.
//
// ponytail: per-element correlation (which result answered which call) needs
// response-body parsing, which arrives with the response extractors; the
// envelope hash is what §4.3 step 6 asks for and it is honest about being one
// envelope, since the identical hash on N records says exactly that.
func (g *gateway) recordResponse(coarse string, calls []string, rw *hashingWriter) {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	rec := ledger.Record{TS: ts}
	if rw.hijacked {
		// A protocol switch leaves through the raw connection: the status line
		// never passes WriteHeader and the tunnel never passes Write, so every
		// captured field here would be fiction. Record why instead — a blank
		// response record is a mystery, a labelled one is a known gap (§7).
		rec.ResourceAttrs = map[string]string{"reason": "protocol switch — response not captured"}
	} else {
		// Absent hash and byte count mean "not captured"; zero bytes means an
		// empty response. The difference is what a reader would get wrong.
		rec.RespHash = fmt.Sprintf("%x", rw.h.Sum(nil))
		rec.Status, rec.Bytes = rw.status, &rw.n
	}
	for _, id := range calls {
		rec.CallID = id
		g.led.AppendResponse(g.partition(coarse), rec)
	}
}

// newCallID mints the join key between a decision and its response (§5.5).
// Random rather than a counter: a counter restarts at zero while the chain it
// writes into resumes, and a collision joins a response to the wrong call —
// misattributed evidence, the failure this ledger exists to prevent.
// crypto/rand.Text is 128+ bits and cannot fail, so there is no empty-ID case
// to leave a record unjoinable.
func newCallID() string { return rand.Text() }

// indeterminate records undecodable/uninspectable traffic (§5.1): forwarded,
// never silently invisible in the ledger. Returns the call_id its record
// carries, so the response can be joined to it.
func (g *gateway) indeterminate(r *http.Request, reason string) string {
	// The body was not inspectable, but the assertion header still is — and a
	// forged token riding a deliberately malformed body is the malformed-MCP
	// evasion case (§8.4), so it must not go unrecorded just because the
	// payload defeated parsing.
	return g.indeterminateCall(coarsePrincipal(r), g.assertionStatus(r.Header.Get(TxnHeader)), reason)
}

// assertionStatus classifies a transaction header without deriving anything
// from it (§5.5: absent | valid | invalid).
func (g *gateway) assertionStatus(txnTok string) string {
	if txnTok == "" {
		return ledger.AssertionAbsent
	}
	if _, err := g.tis.VerifyTxn(txnTok); err != nil {
		return ledger.AssertionInvalid
	}
	return ledger.AssertionValid
}

// effects converts the evaluator's per-policy verdicts into record form. The
// ledger deliberately does not import the policy package: a record is a fact
// about what happened, and it must stay readable by a verifier that has no
// policy engine at all.
func effects(res policy.Result) []ledger.PolicyEffect {
	out := make([]ledger.PolicyEffect, 0, len(res.Effects))
	for _, e := range res.Effects {
		out = append(out, ledger.PolicyEffect{
			PolicyID: e.PolicyID, Decision: string(e.Decision), Mode: e.Mode,
			EnforceAction: e.EnforceAction, OnError: e.OnError,
		})
	}
	return out
}

func (g *gateway) indeterminateCall(coarse, status, reason string) string {
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	ver := g.store.Current().Version
	plan := g.act.Plan(policy.Indeterminate)
	callID := newCallID()
	g.led.Append(g.partition(coarse), ledger.Record{
		TS: ts, CallID: callID, AssertionStatus: status,
		Principal: "svc:" + coarse, PrincipalTier: ledger.TierCoarse,
		Action: "http/request", Decision: string(policy.Indeterminate),
		PolicyMode: ledger.ModeMonitor, ActionApplied: plan.Applied, FailModeApplied: plan.FailMode,
		ResourceAttrs: map[string]string{"reason": reason}, BundleVer: ver,
	})
	g.decisions.Info("decision", "ts", ts, "decision", string(policy.Indeterminate),
		"action_applied", plan.Applied, "assertion_status", status, "reason", reason, "bundle_ver", ver)
	return callID
}

// decide adapts an HTTP request to the transport-agnostic decision path.
func (g *gateway) decide(r *http.Request, c extract.Call, body []byte) string {
	ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
	return g.decideCall(ctx, r.Header.Get(TxnHeader), coarsePrincipal(r), c, body)
}

// decideCall runs identify → classify → decide → attest for one tool call and
// returns the call_id of the record it wrote, which a transport that can see
// the response uses to append the matching response record (§5.5).
// The ledger is the system of record (FR-7); the slog stream is observability.
func (g *gateway) decideCall(ctx context.Context, txnTok, coarse string, c extract.Call, body []byte) string {
	_, span := tracer.Start(ctx, "gurdy.decision", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()
	// Live per-stage timing (internal/clock). Costs ~100ns against a ~300µs
	// decision, and it is the only thing that can answer "how much of the
	// latency is ours" in a deployment rather than in a benchmark.
	defer clock.Decide.Time()()

	// The extractor names the action (§5.3): mcp/tools_call, llm/completion,
	// and whatever a pack adds later all arrive here identically. An
	// unclaimed call still gets a record — the caller only routes traffic it
	// meant to govern, and dropping it silently would be a coverage gap.
	classifyDone := clock.Classify.Time()
	class, ok := extract.Default.Classify(c)
	if !ok {
		class = extract.Result{Action: "unknown", Tool: c.Tool, Attrs: map[string]string{}}
	}
	classifyDone()

	identifyDone := clock.Identify.Time()
	asserted, call, status := g.identify(txnTok, coarse, class.Tool)
	identifyDone()
	attrs, resource := class.Attrs, class.Resource

	// The observed principal is recorded on every call and never degrades
	// (§5.2). It is also what policy evaluates on, so a mintable assertion
	// can add to a record but can never overwrite who the proxy saw.
	// TierOrphan is not reachable from here: both transports always derive a
	// namespaced coarse principal, so there is no "no principal at all" case
	// to represent yet (§5.2 keeps the tier for when one exists).
	principal, tier := "svc:"+coarse, ledger.TierCoarse
	txnID, jti := "", ""
	if call != nil {
		txnID, jti = call.ParentTxn, call.ID
	}
	// Asserted fields exist only when an SDK assertion verified. Otherwise
	// these claims are the proxy's own auto-mint, and writing them here would
	// launder an inference into an agent-side claim (§5.5).
	var assertedPrincipal, assertedActor string
	var assertedScope any
	var lineage []string
	if asserted != nil {
		assertedPrincipal, assertedActor = asserted.Subject, asserted.Act
		assertedScope, lineage = asserted.Scope, asserted.Lineage
	}
	// One evaluator read per decision: the eval and the recorded bundle_ver
	// are always the same bundle, even mid-hot-reload (FR-10).
	ev := g.store.Current()
	evaluateDone := clock.Evaluate.Time()
	res := ev.Evaluate(policy.Input{
		Principal:         principal,
		AssertedPrincipal: assertedPrincipal,
		AssertionStatus:   status,
		Tool:              class.Tool,
		Action:            class.Action,
		Resource:          resource,
		Context:           attrs,
	})
	evaluateDone()
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	// Monitor mode: every policy's rollout state is monitor and the traffic is
	// forwarded regardless of what the policy concluded (ADR-3). Recording the
	// three separately is what makes a decision=block record readable as
	// "would have blocked" rather than as an enforcement claim (§8.3).
	// Act (§4.2). In monitor mode the plan is always "forward"; the record says
	// so explicitly rather than leaving it implied by the absence of blocking
	// code, which is what makes a decision=block record readable as a shadow
	// observation (§8.3).
	plan := g.act.Plan(res.Decision)
	callID := newCallID()
	attestDone := clock.Attest.Time()
	g.led.Append(g.partition(coarse), ledger.Record{
		TS: ts, CallID: callID, TxnID: txnID, AssertionJTI: jti, AssertionStatus: status,
		Principal: principal, PrincipalTier: tier,
		AssertedPrincipal: assertedPrincipal, Lineage: lineage,
		AssertedHumanActor: assertedActor, AssertedScope: assertedScope,
		Tool: class.Tool, Action: class.Action, ResourceAttrs: attrs,
		Decision: string(res.Decision), PolicyMode: ledger.ModeMonitor,
		ActionApplied: plan.Applied, PolicyEffects: effects(res),
		BundleVer: ev.Version, FailModeApplied: plan.FailMode,
		ReqHash: ledger.HashBody(body),
	})
	attestDone()
	span.SetAttributes(
		attribute.String("gurdy.tool", class.Tool),
		attribute.String("gurdy.action", class.Action),
		attribute.String("gurdy.decision", string(res.Decision)),
		// Without the action alongside it, a span reading decision=block claims
		// an enforcement that did not happen — the ledger is disambiguated, so
		// the live telemetry must be too.
		attribute.String("gurdy.action_applied", plan.Applied),
		attribute.StringSlice("gurdy.policy_ids", res.IDs()),
		attribute.String("gurdy.bundle_ver", ev.Version),
		attribute.String("gurdy.txn_id", txnID),
		attribute.String("gurdy.principal_tier", tier),
		attribute.String("gurdy.assertion_status", status),
	)
	g.decisions.Info("decision",
		"ts", ts,
		"txn_id", txnID,
		"assertion_jti", jti,
		"assertion_status", status,
		"principal", principal,
		"principal_tier", tier,
		"asserted_principal", assertedPrincipal,
		"lineage", lineage,
		"tool", class.Tool,
		"action", class.Action,
		"resource", resource,
		"decision", string(res.Decision),
		"action_applied", plan.Applied,
		"policy_ids", res.IDs(),
		"bundle_ver", ev.Version,
	)
	return callID
}

// identify builds the per-call assertion and reports whether the SDK supplied
// a usable one (§5.2). It answers only the *asserted* half of identity — the
// observed principal is derived independently by the caller and does not
// depend on any of this succeeding. Never fails the request.
//
// A DeriveCall/VerifyCall failure returns nil and would otherwise be invisible
// beyond the empty txn fields, so it is counted as a coverage finding (D7) —
// not a distinct assertion status, of which §5.5 defines exactly three.
func (g *gateway) identify(txnTok, coarse, tool string) (*tis.TxnClaims, *tis.CallClaims, string) {
	status := ledger.AssertionAbsent
	var asserted *tis.TxnClaims
	if txnTok != "" {
		claims, err := g.tis.VerifyTxn(txnTok)
		if err != nil {
			status, txnTok = ledger.AssertionInvalid, "" // fall through to coarse
		} else {
			status, asserted = ledger.AssertionValid, claims
		}
	}
	if txnTok == "" {
		txnTok = g.autoMint(coarse)
	}
	// The asserted fields come from the verified txn, not the derived call —
	// DeriveCall copies them verbatim, so sourcing them here keeps a record
	// from reading "assertion_status=valid" with nothing to show for it when
	// the derivation itself fails.
	callTok, err := g.tis.DeriveCall(txnTok, tool)
	if err != nil {
		// The record still gets written, just with empty txn fields — which is
		// indistinguishable from a call that never had an assertion unless the
		// failure is counted. A proxy-internal gap, not a fourth
		// assertion_status: the claim was fine, our derivation was not (§5.5).
		g.led.RecordIdentityGap(g.partition(coarse))
		return asserted, nil, status
	}
	call, err := g.tis.VerifyCall(callTok)
	if err != nil {
		g.led.RecordIdentityGap(g.partition(coarse))
		return asserted, nil, status
	}
	return asserted, call, status
}

// coarsePrincipal derives the attested-coarse principal from the runtime
// environment (§5.2): client host for now; K8s workload identity later.
func coarsePrincipal(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// Namespaced by derivation source, matching the shim's "stdio:" form, so
	// the principal says how it was obtained without a second field. K8s
	// service account / SPIFFE become further namespaces here (§5.2).
	return "host:" + host
}

// autoMint returns a live txn token for a coarse principal, minting on first
// sight or after expiry (§4.3 "proxy auto-mints on first unseen task ID").
// The fast path is a clock comparison under a read lock. It used to be an
// ES256 verify under a process-wide exclusive lock, which put a signature
// check and a mutex on the *common* path — every call arriving without a
// Gurdy-Txn, which is every call from an agent with no SDK installed. Measured
// at 70,970 ns/op parallel against 33,020 with a txn supplied, identical
// crypto: 2.15x of pure contention (D12).
//
// Re-verifying proved nothing extra anyway. We minted this token ourselves and
// hold it in memory, so the only claim VerifyTxn could refute is expiry, and
// expiry is a value we already had at mint time.
//
// ponytail: expiry is the only staleness this understands. A rotated signing
// key (NFR-5, not built) would leave cached tokens that pass the clock check
// and fail verification downstream — rotation must flush this map, and the
// nearest hook is where the new key is installed.
func (g *gateway) autoMint(coarse string) string {
	now := time.Now()

	g.mu.RLock()
	ent, ok := g.autoTxn[coarse]
	g.mu.RUnlock()
	if ok && now.Before(ent.exp) {
		return ent.tok
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	// Re-check under the write lock: several goroutines can miss the fast path
	// on the same principal at once, and without this they would each mint,
	// each overwrite, and hand out tokens the others had already replaced.
	if ent, ok := g.autoTxn[coarse]; ok && now.Before(ent.exp) {
		return ent.tok
	}
	// Minting is rare — once per principal per (TTL - autoRenew) — so this is
	// the one place a sweep is affordable. Without it the map keeps an entry
	// for every client IP ever seen, which is the D6 leak; with it the map is
	// bounded by principals *currently* active rather than by history.
	for k, v := range g.autoTxn {
		if !now.Before(v.exp) {
			delete(g.autoTxn, k)
		}
	}

	top := tis.Scope{Compartments: []string{"*"}, ResourceTypes: []string{"*"},
		Actions: []string{"*"}, Purpose: "*"}
	tok, err := g.tis.MintTxn("svc:"+coarse, "", top, g.store.Current().Version, 0)
	if err != nil {
		return ""
	}
	// Read the expiry back from the token rather than recomputing now+TTL: TTL
	// clamping lives in MintTxn, so a recomputed expiry would be this code's
	// opinion of when the token dies instead of the token's.
	claims, err := g.tis.VerifyTxn(tok)
	if err != nil {
		return "" // freshly minted and unverifiable; do not cache it
	}
	g.autoTxn[coarse] = autoTok{tok: tok, exp: claims.ExpiresAt.Time.Add(-autoRenew)}
	return tok
}
