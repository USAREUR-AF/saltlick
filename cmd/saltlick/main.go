// Command saltlick serves a peering directory that grants nothing.
//
// A party publishes its own interconnection capability here so that two
// organisations can check compatibility before they build anything between
// them. The directory is advisory, never authoritative: being listed grants
// access to nothing, and federation works with this service switched off.
//
// Subcommands:
//
//	serve    run the HTTP directory
//	clear    remove an entry whose key was lost -- an administrative act, logged
//	log      print the administrative log
//	keygen   generate an Ed25519 keypair in the encoding the API expects
//	sign     sign a package, and print the headers a publish needs
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/usareur-af/saltlick/internal/canonical"
	"github.com/usareur-af/saltlick/internal/httpapi"
	"github.com/usareur-af/saltlick/internal/pkgv1"
	"github.com/usareur-af/saltlick/internal/store"
	"github.com/usareur-af/saltlick/internal/writeauth"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "saltlick: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("no subcommand given")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "clear":
		return clear(args[1:])
	case "log":
		return printLog(args[1:])
	case "keygen":
		return keygen(args[1:])
	case "sign":
		return sign(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `saltlick -- a peering directory that grants nothing

  saltlick serve  [-addr :8080] [-db saltlick.db] [-trusted-proxies <cidrs>]
                  [-read-limit 10/s] [-read-burst 30] [-write-limit 6/m] [-write-burst 6]
  saltlick clear  -db saltlick.db -id <sovereign_id> -reason <text>
  saltlick log    -db saltlick.db
  saltlick keygen [-out <prefix>]
  saltlick sign   -key <file> -package <file> [-id <sovereign_id>]
  saltlick sign   -key <file> -upload package|packages/<counterparty>|ca|spiffe-bundle -file <file> -id <sovereign_id>
  saltlick sign   -key <file> -method DELETE -id <sovereign_id> [-upload packages/<counterparty>]

Advisory only. Being listed grants access to nothing, and nothing here
establishes that a party is who it claims to be.
`)
}

// defaultAddr is loopback, for a bare local run. A deployment puts the service
// behind a TLS proxy or load balancer that is reachable from the internet, and
// sets SALTLICK_ADDR to the address that proxy forwards to; the container image
// sets SALTLICK_ADDR=:8080, because inside a container binding loopback would
// make the service unreachable to its own proxy.
const defaultAddr = "127.0.0.1:8080"

// Per-source defaults. A reader browsing the catalogue makes a handful of
// requests; a party publishes once per package and rotates rarely.
const (
	defaultReadLimit  = "10/s"
	defaultReadBurst  = 30
	defaultWriteLimit = "6/m"
	defaultWriteBurst = 6
)

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", envOr("SALTLICK_ADDR", defaultAddr), "listen address")
	dbPath := fs.String("db", envOr("SALTLICK_DB", "saltlick.db"), "SQLite database file")
	readLimit := fs.String("read-limit", envOr("SALTLICK_READ_LIMIT", defaultReadLimit),
		"per-source sustained rate for GET: N/s, N/m or N/h; 0 disables")
	readBurst := fs.Int("read-burst", envInt("SALTLICK_READ_BURST", defaultReadBurst),
		"per-source burst for GET")
	writeLimit := fs.String("write-limit", envOr("SALTLICK_WRITE_LIMIT", defaultWriteLimit),
		"per-source sustained rate for PUT and DELETE: N/s, N/m or N/h; 0 disables")
	writeBurst := fs.Int("write-burst", envInt("SALTLICK_WRITE_BURST", defaultWriteBurst),
		"per-source burst for PUT and DELETE")
	trustedProxies := fs.String("trusted-proxies", os.Getenv("SALTLICK_TRUSTED_PROXIES"),
		"comma-separated CIDRs of the proxies whose X-Forwarded-For is believed; empty trusts none")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	read, err := httpapi.ParseRate(*readLimit)
	if err != nil {
		return fmt.Errorf("-read-limit: %w", err)
	}
	write, err := httpapi.ParseRate(*writeLimit)
	if err != nil {
		return fmt.Errorf("-write-limit: %w", err)
	}
	proxies, err := httpapi.ParsePrefixes(*trustedProxies)
	if err != nil {
		return fmt.Errorf("-trusted-proxies: %w", err)
	}

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := httpapi.New(st, log, time.Now)
	limiter := httpapi.NewLimiter(httpapi.LimitConfig{
		Read:           read,
		ReadBurst:      *readBurst,
		Write:          write,
		WriteBurst:     *writeBurst,
		TrustedProxies: proxies,
	}, time.Now)
	log.Info("per-source limits",
		"read", *readLimit, "read_burst", *readBurst,
		"write", *writeLimit, "write_burst", *writeBurst,
		"trusted_proxies", *trustedProxies)
	return httpapi.Serve(ctx, *addr, limiter.Wrap(srv.Handler()), log)
}

// clear removes an entry. It is the answer to a party that has lost its signing
// key: the trust-on-first-use binding cannot be replaced without the key it
// replaces, so a human removes the entry and the party publishes afresh. It is
// deliberately not an HTTP endpoint -- an operator with the database file does
// this, and it is written to the administrative log.
func clear(args []string) error {
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	dbPath := fs.String("db", envOr("SALTLICK_DB", "saltlick.db"), "SQLite database file")
	id := fs.String("id", "", "sovereign_id to clear")
	reason := fs.String("reason", "", "why the entry is being cleared (recorded in the log)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" || *reason == "" {
		return errors.New("clear needs -id and -reason")
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	st.Lock()
	defer st.Unlock()
	if err := st.Delete(ctx, *id); err != nil {
		return err
	}
	if err := st.AppendLog(ctx, "clear", *id, "cleared by operator: "+*reason, time.Now()); err != nil {
		return err
	}
	fmt.Printf("cleared %s; the next publish for it binds a new key on first use\n", *id)
	return nil
}

func printLog(args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	dbPath := fs.String("db", envOr("SALTLICK_DB", "saltlick.db"), "SQLite database file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()
	entries, err := st.Log(context.Background())
	if err != nil {
		return err
	}
	for _, e := range entries {
		fmt.Printf("%s  %-7s %-16s %s\n", e.At.Format(time.RFC3339), e.Action, e.SovereignID, e.Detail)
	}
	return nil
}

// keygen writes a keypair in the encodings the specification fixes: the
// verifying key is the 32 raw bytes, base64, 44 characters ending in one '='.
// Not PEM, not DER, not OpenSSH -- those decode to different bytes or do not
// decode at all, and a channel that carries a key by telephone has no file
// extension to disambiguate them.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	out := fs.String("out", "", "write <prefix>.key and <prefix>.pub instead of printing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	privB64 := base64.StdEncoding.EncodeToString(priv.Seed())
	if *out == "" {
		fmt.Printf("verifying key (44 chars, one '='):  %s\n", pubB64)
		fmt.Printf("signing seed  (KEEP SECRET):        %s\n", privB64)
		fmt.Println()
		fmt.Println("Read the verifying key to your counterparty in eleven groups of four characters,")
		fmt.Println("state the group count first, and have them read it back. That human step is what")
		fmt.Println("binds the key. Learning it from this directory instead binds you to whoever runs")
		fmt.Println("the directory.")
		return nil
	}
	if err := os.WriteFile(*out+".key", []byte(privB64+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(*out+".pub", []byte(pubB64+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s.key (secret, mode 0600) and %s.pub\n", *out, *out)
	return nil
}

// sign signs a package and prints the request headers a publish needs. It is a
// convenience for operating this service; a party may equally sign with any
// Ed25519 implementation, which is the point of the format.
func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyFile := fs.String("key", "", "file holding the base64 signing seed (from keygen)")
	pkgFile := fs.String("package", "", "package JSON to sign; '-' for stdin")
	method := fs.String("method", http.MethodPut, "request method the headers are for")
	idFlag := fs.String("id", "", "sovereign_id (defaults to the one in the package)")
	outFile := fs.String("out", "", "write the signed package here instead of stdout")
	upload := fs.String("upload", "", "print the headers to host a file beside the entry: package, packages/<counterparty>, ca or spiffe-bundle (with -file and -id)")
	uploadFile := fs.String("file", "", "the file to upload with -upload; sent unchanged")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile == "" {
		return errors.New("sign needs -key")
	}
	seedB64, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedB64)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%s does not hold a base64 %d-byte Ed25519 seed", *keyFile, ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	if *method == http.MethodDelete {
		id := *idFlag
		if id == "" {
			return errors.New("a delete needs -id")
		}
		resource := id
		if cp, ok := strings.CutPrefix(*upload, "packages/"); ok {
			// Withdraw one counterparty's package: -method DELETE -upload packages/<counterparty>.
			if !pkgv1.ValidSovereignID(cp) || cp == id {
				return errors.New("-upload packages/<counterparty> names another party's sovereign_id")
			}
			resource = id + "/" + *upload
		} else if *upload != "" {
			return errors.New("a delete takes no -upload, or -upload packages/<counterparty> to withdraw one counterparty's package")
		}
		stmt := writeauth.Statement(http.MethodDelete, resource, nil, "")
		fmt.Printf("%s: %s\n", httpapi.HeaderSignature, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, stmt)))
		return nil
	}

	if *upload != "" {
		cp, perCounterparty := strings.CutPrefix(*upload, "packages/")
		switch {
		case *upload == "package" || *upload == "ca" || *upload == "spiffe-bundle":
		case perCounterparty && pkgv1.ValidSovereignID(cp) && cp != *idFlag:
		default:
			return errors.New("-upload is package, packages/<counterparty>, ca or spiffe-bundle; " +
				"the counterparty is another party's sovereign_id")
		}
		if *idFlag == "" || *uploadFile == "" {
			return errors.New("-upload needs -id and -file")
		}
		body, err := os.ReadFile(*uploadFile)
		if err != nil {
			return err
		}
		stmt := writeauth.Statement(http.MethodPut, *idFlag+"/"+*upload, body, pubB64)
		fmt.Printf("%s: %s\n%s: %s\n", httpapi.HeaderKey, pubB64,
			httpapi.HeaderSignature, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, stmt)))
		return nil
	}

	if *pkgFile == "" {
		return errors.New("sign needs -package")
	}
	var raw []byte
	if *pkgFile == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(*pkgFile)
	}
	if err != nil {
		return err
	}

	// Sign the canonical form of the package with any existing signature member
	// removed, then emit the canonical form with the signature in place. The
	// emitted bytes are what gets published and what the signature covers.
	doc, err := canonical.Parse(raw)
	if err != nil {
		return err
	}
	input, err := canonical.Write(doc.Without("signature"))
	if err != nil {
		return err
	}
	sigB64 := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, input))
	signed := doc.Without("signature")
	signed.Members = append(signed.Members, canonical.Member{
		Name:  "signature",
		Value: &canonical.Value{Kind: canonical.KindString, Str: sigB64},
	})
	body, err := canonical.Write(signed)
	if err != nil {
		return err
	}

	pkg, err := pkgv1.Parse(body)
	if err != nil {
		return fmt.Errorf("the signed result is not a valid directory entry: %w", err)
	}
	id := *idFlag
	if id == "" {
		id = pkg.SovereignID
	}
	stmt := writeauth.Statement(*method, id, body, pubB64)
	reqSig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, stmt))

	if *outFile != "" {
		if err := os.WriteFile(*outFile, body, 0o644); err != nil {
			return err
		}
	} else {
		os.Stdout.Write(body)
		fmt.Println()
	}
	fmt.Fprintf(os.Stderr, "\n%s: %s\n%s: %s\n", httpapi.HeaderKey, pubB64, httpapi.HeaderSignature, reqSig)
	return nil
}

// envInt reads an integer from the environment. A value that does not parse
// stops the process rather than falling back silently to the default.
func envInt(name string, fallback int) int {
	v := os.Getenv(name)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "saltlick: %s=%q is not an integer\n", name, v)
		os.Exit(2)
	}
	return n
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
