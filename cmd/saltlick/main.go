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

  saltlick serve  [-addr :8080] [-db saltlick.db]
  saltlick clear  -db saltlick.db -id <sovereign_id> -reason <text>
  saltlick log    -db saltlick.db
  saltlick keygen [-out <prefix>]
  saltlick sign   -key <file> -package <file> [-id <sovereign_id>]

Advisory only. Being listed grants access to nothing, and nothing here
establishes that a party is who it claims to be.
`)
}

// defaultAddr is loopback, not every interface. The directory is mesh-internal:
// a partner is not expected to reach it, and federation is unharmed when one
// cannot, because a package is self-verifying and can be handed over by any
// means. Defaulting to a routable bind would make an accidental exposure the
// path of least resistance.
//
// A container overrides this. Inside a container the network namespace is the
// boundary, so the image sets SALTLICK_ADDR=:8080 -- binding loopback there
// would make the service unreachable to its own reverse proxy or load balancer.
const defaultAddr = "127.0.0.1:8080"

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", envOr("SALTLICK_ADDR", defaultAddr), "listen address")
	dbPath := fs.String("db", envOr("SALTLICK_DB", "saltlick.db"), "SQLite database file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	st, err := store.Open(*dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := httpapi.New(st, log, time.Now)
	return httpapi.Serve(ctx, *addr, srv.Handler(), log)
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
		stmt := writeauth.Statement(http.MethodDelete, id, nil, "")
		fmt.Printf("%s: %s\n", httpapi.HeaderSignature, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, stmt)))
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

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
