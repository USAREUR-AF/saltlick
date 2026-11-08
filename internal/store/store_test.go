package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

// A database whose hosted table predates the writer_key and signature columns
// opens, keeps its rows, and serves them with empty signature fields.
func TestOpenAddsTheHostedSignatureColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE hosted (
  sovereign_id TEXT NOT NULL,
  kind         TEXT NOT NULL,
  body         BLOB NOT NULL,
  updated      TEXT NOT NULL,
  PRIMARY KEY (sovereign_id, kind)
);
INSERT INTO hosted VALUES ('xaa', 'ca', x'0102', '2026-11-01T00:00:00Z');`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	ctx := context.Background()
	for i := 0; i < 2; i++ { // opening twice adds nothing twice
		st, err := Open(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		f, err := st.GetFile(ctx, "xaa", KindCA)
		if err != nil {
			t.Fatal(err)
		}
		if string(f.Body) != "\x01\x02" || f.WriterKey != "" || f.Signature != "" {
			t.Fatalf("old row read back as %+v", f)
		}
		st.Close()
	}

	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.PutFile(ctx, "xaa", KindCA, &HostedFile{Body: []byte{3}, WriterKey: "k", Signature: "s"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	f, err := st.GetFile(ctx, "xaa", KindCA)
	if err != nil {
		t.Fatal(err)
	}
	if string(f.Body) != "\x03" || f.WriterKey != "k" || f.Signature != "s" {
		t.Fatalf("replaced row read back as %+v", f)
	}
}
