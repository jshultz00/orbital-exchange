package handlers

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

// Legacy serves the decommissioned-crew archive: a public dump of
// historical roster rows whose passwords are stored as raw unsalted MD5
// hashes. PLANTED VULN a02-weak-password-hash. The archive page lists
// every record (username + hash) and a "verify identity" form. Submitting
// a plaintext whose MD5 matches any listed hash flips the tracker.
type Legacy struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

const weakPasswordHashTrackerID = "a02-weak-password-hash"

type legacyRow struct {
	Username string
	MD5Hash  string
	Role     string
}

func (l *Legacy) Index(w http.ResponseWriter, r *http.Request) {
	rows, err := l.fetchRows()
	if err != nil {
		log.Printf("legacy archive list: %v", err)
		http.Error(w, "archive read failed", http.StatusInternalServerError)
		return
	}

	data := pageData(r, l.Session, "Decommissioned Crew Archive")
	data["Rows"] = rows
	render(w, l.Views, "archive", data)
}

// Verify accepts a username + plaintext, MD5-hashes the plaintext, and
// compares to the archive row. A match flips the tracker. There is no
// rate limit and no constant-time compare — cracking is the lesson.
func (l *Legacy) Verify(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	plaintext := r.PostFormValue("password")

	rows, err := l.fetchRows()
	if err != nil {
		log.Printf("legacy verify list: %v", err)
		http.Error(w, "archive read failed", http.StatusInternalServerError)
		return
	}

	sum := md5.Sum([]byte(plaintext))
	submitted := hex.EncodeToString(sum[:])

	var matched *legacyRow
	for i := range rows {
		if rows[i].Username == username && rows[i].MD5Hash == submitted {
			matched = &rows[i]
			break
		}
	}

	data := pageData(r, l.Session, "Decommissioned Crew Archive")
	data["Rows"] = rows
	data["AttemptUser"] = username
	data["AttemptHash"] = submitted

	if matched != nil {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := l.DB.Exec(flip, weakPasswordHashTrackerID); err != nil {
			log.Printf("legacy verify discover flip: %v", err)
		}
		data["VerifySuccess"] = "Hash collision confirmed for " + matched.Username + " (" + matched.Role + ")."
	} else {
		data["VerifyError"] = "No archive record matched that plaintext."
	}

	render(w, l.Views, "archive", data)
}

func (l *Legacy) fetchRows() ([]legacyRow, error) {
	rows, err := l.DB.Query(`SELECT username, md5_hash, role FROM legacy_users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []legacyRow
	for rows.Next() {
		var r legacyRow
		if err := rows.Scan(&r.Username, &r.MD5Hash, &r.Role); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
