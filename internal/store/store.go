// Package store persists directory entries in a single SQLite file.
//
// One rule governs the schema: the package column holds the bytes exactly as
// they were submitted, as a BLOB, and nothing in this repository rewrites them.
// The same holds for the hosted table, which keeps a party's package, CA
// certificate and SPIFFE trust bundle beside its entry, each with the key and
// request signature that wrote it.
// A consumer verifies a signature over exactly what was signed, so any
// re-serialisation -- re-ordering members, re-indenting, round-tripping through
// a struct -- destroys the entry's only useful property.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver: no cgo, so the binary stays static
)

// ErrNotFound is returned when no entry exists for a sovereign_id.
var ErrNotFound = errors.New("no entry for that sovereign_id")

// Entry is one stored directory entry.
type Entry struct {
	SovereignID string
	Package     []byte // the submitted bytes, byte-for-byte
	BoundKey    string // base64 raw Ed25519 verifying key, bound on first use
	Issued      string
	Expires     string
	FirstSeen   time.Time
	Updated     time.Time
}

// Store is a directory's storage. Writes are serialised by a mutex: the
// trust-on-first-use decision is a read followed by a write that must not
// interleave with another writer, and one process with one SQLite file needs
// nothing more elaborate than this to make that true.
type Store struct {
	db      *sql.DB
	writeMu sync.Mutex
}

const schema = `
CREATE TABLE IF NOT EXISTS entries (
  sovereign_id TEXT PRIMARY KEY,
  package      BLOB NOT NULL,
  bound_key    TEXT NOT NULL,
  issued       TEXT NOT NULL,
  expires      TEXT NOT NULL,
  first_seen   TEXT NOT NULL,
  updated      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosted (
  sovereign_id TEXT NOT NULL,
  kind         TEXT NOT NULL,
  body         BLOB NOT NULL,
  updated      TEXT NOT NULL,
  writer_key   TEXT NOT NULL DEFAULT '',
  signature    TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (sovereign_id, kind)
);
CREATE TABLE IF NOT EXISTS admin_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  at           TEXT NOT NULL,
  action       TEXT NOT NULL,
  sovereign_id TEXT NOT NULL,
  detail       TEXT NOT NULL
);
`

// Open opens or creates the directory database at path. Use ":memory:" for a
// throwaway one.
func Open(path string) (*Store, error) {
	dsn := path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_txlock=immediate"
	if path == ":memory:" {
		dsn = path
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	// One connection keeps an in-memory database from being several distinct
	// databases, and costs nothing at a directory's request rate.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	if err := addHostedSignatureColumns(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("adding the hosted signature columns: %w", err)
	}
	return &Store{db: db}, nil
}

// addHostedSignatureColumns brings a hosted table created without the
// writer_key and signature columns up to the current schema. A row stored
// without them keeps empty values and is served without the signature headers.
func addHostedSignatureColumns(db *sql.DB) error {
	rows, err := db.Query(`SELECT name FROM pragma_table_info('hosted')`)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, col := range []string{"writer_key", "signature"} {
		if have[col] {
			continue
		}
		if _, err := db.Exec(`ALTER TABLE hosted ADD COLUMN ` + col + ` TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// Lock takes the write lock. A caller that reads an entry, decides whether a
// write is permitted, and then writes must hold it across all three steps.
func (s *Store) Lock()   { s.writeMu.Lock() }
func (s *Store) Unlock() { s.writeMu.Unlock() }

// Get returns one entry, or ErrNotFound.
func (s *Store) Get(ctx context.Context, id string) (*Entry, error) {
	var e Entry
	var firstSeen, updated string
	err := s.db.QueryRowContext(ctx,
		`SELECT sovereign_id, package, bound_key, issued, expires, first_seen, updated
		   FROM entries WHERE sovereign_id = ?`, id,
	).Scan(&e.SovereignID, &e.Package, &e.BoundKey, &e.Issued, &e.Expires, &firstSeen, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	e.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
	e.Updated, _ = time.Parse(time.RFC3339, updated)
	return &e, nil
}

// List returns every entry's metadata, ordered by sovereign_id. The package
// bytes are not loaded: the list is a catalogue, and a reader who wants an
// entry fetches it.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT sovereign_id, package, bound_key, issued, expires, first_seen, updated
		   FROM entries ORDER BY sovereign_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		var firstSeen, updated string
		if err := rows.Scan(&e.SovereignID, &e.Package, &e.BoundKey, &e.Issued, &e.Expires, &firstSeen, &updated); err != nil {
			return nil, err
		}
		e.FirstSeen, _ = time.Parse(time.RFC3339, firstSeen)
		e.Updated, _ = time.Parse(time.RFC3339, updated)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Put inserts or replaces an entry, preserving first_seen across a replace.
// The caller is responsible for having decided that this write is permitted;
// Put enforces nothing about keys.
func (s *Store) Put(ctx context.Context, e *Entry, now time.Time) error {
	ts := now.UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO entries (sovereign_id, package, bound_key, issued, expires, first_seen, updated)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(sovereign_id) DO UPDATE SET
		   package    = excluded.package,
		   bound_key  = excluded.bound_key,
		   issued     = excluded.issued,
		   expires    = excluded.expires,
		   updated    = excluded.updated`,
		e.SovereignID, e.Package, e.BoundKey, e.Issued, e.Expires, ts, ts)
	return err
}

// Delete removes an entry and every file hosted for it, in one transaction.
// It returns ErrNotFound if there was no entry.
func (s *Store) Delete(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // a no-op after Commit
	res, err := tx.ExecContext(ctx, `DELETE FROM entries WHERE sovereign_id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM hosted WHERE sovereign_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// The kinds of file a party may host beside its entry.
const (
	KindPackage      = "package"       // the party's signed federation package, canonical bytes
	KindCA           = "ca"            // the party's CA certificate(s), PEM
	KindSPIFFEBundle = "spiffe-bundle" // the party's SPIFFE trust bundle, JSON
)

// ErrNoFile is returned when a party hosts no file of the kind asked for.
var ErrNoFile = errors.New("no file of that kind for that sovereign_id")

// HostedFile is a file kept beside an entry, with the write that stored it.
type HostedFile struct {
	Body []byte // exactly as received
	// WriterKey is the X-Saltlick-Key value the upload presented, exactly as
	// presented: the key line of the request statement Signature covers.
	WriterKey string
	// Signature is the upload's request signature, base64. Empty for a row
	// stored before the column existed.
	Signature string
	Updated   time.Time
}

// PutFile stores a hosted file exactly as received, with the key and request
// signature that wrote it, replacing any earlier one of the same kind. The
// caller has decided the write is permitted.
func (s *Store) PutFile(ctx context.Context, id, kind string, f *HostedFile, now time.Time) (replaced bool, err error) {
	var one int
	err = s.db.QueryRowContext(ctx, `SELECT 1 FROM hosted WHERE sovereign_id = ? AND kind = ?`, id, kind).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, err
	default:
		replaced = true
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO hosted (sovereign_id, kind, body, updated, writer_key, signature) VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(sovereign_id, kind) DO UPDATE SET
		   body = excluded.body, updated = excluded.updated,
		   writer_key = excluded.writer_key, signature = excluded.signature`,
		id, kind, f.Body, now.UTC().Format(time.RFC3339), f.WriterKey, f.Signature)
	return replaced, err
}

// GetFile returns a hosted file, or ErrNoFile.
func (s *Store) GetFile(ctx context.Context, id, kind string) (*HostedFile, error) {
	var f HostedFile
	var updated string
	err := s.db.QueryRowContext(ctx,
		`SELECT body, writer_key, signature, updated FROM hosted WHERE sovereign_id = ? AND kind = ?`, id, kind,
	).Scan(&f.Body, &f.WriterKey, &f.Signature, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoFile
	}
	if err != nil {
		return nil, err
	}
	if f.Body == nil {
		f.Body = []byte{}
	}
	f.Updated, _ = time.Parse(time.RFC3339, updated)
	return &f, nil
}

// HostedKinds returns, per sovereign_id, the kinds of file it hosts.
func (s *Store) HostedKinds(ctx context.Context) (map[string]map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sovereign_id, kind FROM hosted`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]bool{}
	for rows.Next() {
		var id, kind string
		if err := rows.Scan(&id, &kind); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]bool{}
		}
		out[id][kind] = true
	}
	return out, rows.Err()
}

// AppendLog records an act against an entry. Two acts are recorded: a key
// rotation, so that a directory compromise is detectable after the fact, and an
// operator clearing an entry whose key was lost, which is a plainly
// administrative act and is logged as one.
func (s *Store) AppendLog(ctx context.Context, action, id, detail string, now time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO admin_log (at, action, sovereign_id, detail) VALUES (?, ?, ?, ?)`,
		now.UTC().Format(time.RFC3339), action, id, detail)
	return err
}

// LogEntry is one row of the administrative log.
type LogEntry struct {
	At          time.Time
	Action      string
	SovereignID string
	Detail      string
}

// Log returns the administrative log, oldest first.
func (s *Store) Log(ctx context.Context) ([]LogEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT at, action, sovereign_id, detail FROM admin_log ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogEntry{}
	for rows.Next() {
		var l LogEntry
		var at string
		if err := rows.Scan(&at, &l.Action, &l.SovereignID, &l.Detail); err != nil {
			return nil, err
		}
		l.At, _ = time.Parse(time.RFC3339, at)
		out = append(out, l)
	}
	return out, rows.Err()
}
