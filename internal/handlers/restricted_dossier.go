package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/views"
)

const failOpenTrackerID = "a10-fail-open-authorization"

// RestrictedDossier is the planted A10:2025 handler for tracker row
// "a10-fail-open-authorization".
//
// In-fiction: Station Command Intel Archive, restricted to admins or crew who
// hold a valid clearance token issued by Command. The token check builds its
// SQL query via fmt.Sprintf (raw string concatenation). A token containing a
// single quote triggers a SQLite parse error. The error handler logs the
// failure but falls through instead of returning 403 — granting access to any
// crew member who can provoke that error.
type RestrictedDossier struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// IntelRecord is one summary row shown on the restricted dossier page.
type IntelRecord struct {
	Username      string
	ManifestCount int
	TotalCredits  int
}

// Page handles GET /bridge/restricted-dossier.
//
// Access control:
//  1. Must be authenticated.
//  2. No ?token= → admin only; non-admins get 403.
//  3. ?token= present → looked up in crew_clearances via raw SQL.
//     ErrNoRows → 403 (token unknown).
//     Any other error → PLANTED VULN: falls through instead of denying.
//     Match but wrong user → 403 (token belongs to someone else).
func (rd *RestrictedDossier) Page(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, rd.Session)
	if user == nil {
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		if !user.IsAdmin {
			http.Error(w, "Station Command access only. Supply a clearance token if you have one.", http.StatusForbidden)
			return
		}
	} else {
		// PLANTED VULN a10-fail-open-authorization: token is interpolated
		// directly into the query string. A value like "foo'" produces broken
		// SQL; SQLite returns a parse error. The safe response is to deny, but
		// the error branch below logs and falls through — granting access.
		q := fmt.Sprintf(
			"SELECT user_id FROM crew_clearances WHERE token = '%s'",
			token,
		)
		var grantedUID int64
		err := rd.DB.QueryRow(q).Scan(&grantedUID)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "Invalid clearance token.", http.StatusForbidden)
			return
		}
		if err != nil {
			// VULNERABLE BY DESIGN: a crafted token can cause the query to
			// fail here (e.g., an unmatched quote triggers a SQLite syntax
			// error). The correct response is to deny; instead we log and
			// fall through — this is the "fail open" lesson.
			log.Printf("restricted dossier clearance check error: %v (token=%q)", err, token)
			// intentional fall-through
		} else if grantedUID != user.ID {
			http.Error(w, "Clearance token is not yours.", http.StatusForbidden)
			return
		}
	}

	// If a non-admin reached this line via the error fall-through, flip the tracker.
	if !user.IsAdmin {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, err := rd.DB.Exec(flip, failOpenTrackerID); err != nil {
			log.Printf("fail-open discover flip: %v", err)
		}
	}

	intel, err := rd.loadIntel()
	if err != nil {
		log.Printf("restricted dossier intel load: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := pageData(r, rd.Session, "Restricted Intel Dossier")
	data["Intel"] = intel
	render(w, rd.Views, "restricted_dossier", data)
}

func (rd *RestrictedDossier) loadIntel() ([]IntelRecord, error) {
	const q = `
		SELECT u.username,
		       COUNT(m.id),
		       COALESCE(SUM(m.total_credits), 0)
		FROM users u
		LEFT JOIN manifests m ON m.user_id = u.id
		GROUP BY u.id, u.username
		ORDER BY u.username
	`
	rows, err := rd.DB.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []IntelRecord
	for rows.Next() {
		var rec IntelRecord
		if err := rows.Scan(&rec.Username, &rec.ManifestCount, &rec.TotalCredits); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}
