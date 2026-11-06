// Package store persists directory entries in a single SQLite file.
//
// One rule governs the schema: the package column holds the bytes exactly as
// they were submitted, as a BLOB, and nothing in this repository rewrites them.
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
	return &Store{db: db}, nil
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

// Delete removes an entry. It returns ErrNotFound if there was none.
func (s *Store) Delete(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM entries WHERE sovereign_id = ?`, id)
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
	return nil
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
