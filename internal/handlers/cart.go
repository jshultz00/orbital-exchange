package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

// promoReplayTrackerID is the planted A04 (Insecure Design) row flipped when
// a crew member redeems the same voucher code more than once. The redemption
// flow validates the code but never marks it spent.
const promoReplayTrackerID = "a06-promo-code-replay"

// cartTamperTrackerID is the planted A01 row flipped when a checkout submits
// a unit price or qty lower than the canonical product value in the DB.
const cartTamperTrackerID = "a01-cart-price-tampering"

// voucherSessionKey holds the comma-separated list of voucher codes the
// current crew member has applied to their cart in this session.
const voucherSessionKey = "applied_vouchers"

// Cart handles the per-user shopping cart.
//
// Defensive baseline:
//   - Requires authentication (guests redirected to /login).
//   - Reads product price/stock from the DB on add — client-submitted price
//     is ignored (planted vuln a01-cart-price-tampering will deliberately
//     break this later).
//   - Quantity bounded by stock with a server-side check.
type Cart struct {
	DB      *sql.DB
	Views   *views.Views
	Session *scs.SessionManager
}

// CartLine is a joined row of cart_items + products for the view.
type CartLine struct {
	ProductID   int64
	Slug        string
	Name        string
	UnitPrice   int
	Qty         int
	Subtotal    int
	Description string
}

// View renders /cart for the current user.
func (c *Cart) View(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}

	const q = `
		SELECT p.id, p.slug, p.name, p.description, p.price, ci.qty
		FROM cart_items ci
		JOIN products p ON p.id = ci.product_id
		WHERE ci.user_id = ?
		ORDER BY ci.created_at
	`
	rows, err := c.DB.Query(q, user.ID)
	if err != nil {
		log.Printf("cart view query: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var lines []CartLine
	total := 0
	for rows.Next() {
		var l CartLine
		if err := rows.Scan(&l.ProductID, &l.Slug, &l.Name, &l.Description, &l.UnitPrice, &l.Qty); err != nil {
			log.Printf("cart view scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		l.Subtotal = l.UnitPrice * l.Qty
		total += l.Subtotal
		lines = append(lines, l)
	}

	applied, discount := c.appliedVouchers(r)
	finalTotal := total - discount
	if finalTotal < 0 {
		finalTotal = 0
	}

	data := pageData(r, c.Session, "Cart")
	data["Lines"] = lines
	data["Total"] = total
	data["Vouchers"] = applied
	data["Discount"] = discount
	data["FinalTotal"] = finalTotal
	render(w, c.Views, "cart", data)
}

// AppliedVoucher pairs a redeemed code with its discount for the cart view.
type AppliedVoucher struct {
	Code     string
	Discount int
}

// ApplyVoucher handles POST /cart/voucher. Looks up the submitted code,
// confirms it exists, appends it to the session list, and re-renders the
// cart. The code is intentionally NOT marked as consumed — replays stack.
func (c *Cart) ApplyVoucher(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	code := strings.ToUpper(strings.TrimSpace(r.PostFormValue("code")))
	if code == "" {
		c.flash(r, "Enter a voucher code.")
		http.Redirect(w, r, "/cart", http.StatusSeeOther)
		return
	}

	var discount int
	err := c.DB.QueryRow(`SELECT discount FROM vouchers WHERE code = ?`, code).Scan(&discount)
	if errors.Is(err, sql.ErrNoRows) {
		c.flash(r, "Voucher not recognized.")
		http.Redirect(w, r, "/cart", http.StatusSeeOther)
		return
	}
	if err != nil {
		log.Printf("voucher lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	current := c.Session.GetString(r.Context(), voucherSessionKey)
	codes := splitCodes(current)
	for _, existing := range codes {
		if existing == code {
			// Replay confirmed — flip the tracker row.
			const flip = `
				UPDATE vulnerabilities
				SET status = 'discovered',
				    discovered_at = CURRENT_TIMESTAMP
				WHERE id = ? AND status = 'undiscovered'
			`
			if _, ferr := c.DB.Exec(flip, promoReplayTrackerID); ferr != nil {
				log.Printf("voucher replay discover flip: %v", ferr)
			}
			break
		}
	}
	codes = append(codes, code)
	c.Session.Put(r.Context(), voucherSessionKey, strings.Join(codes, ","))
	c.flash(r, "Voucher "+code+" applied (-"+strconv.Itoa(discount)+" cr).")
	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

// appliedVouchers resolves session-stored codes back to discount values and
// returns the rendered list plus total discount.
func (c *Cart) appliedVouchers(r *http.Request) ([]AppliedVoucher, int) {
	raw := c.Session.GetString(r.Context(), voucherSessionKey)
	codes := splitCodes(raw)
	if len(codes) == 0 {
		return nil, 0
	}
	out := make([]AppliedVoucher, 0, len(codes))
	total := 0
	for _, code := range codes {
		var d int
		if err := c.DB.QueryRow(`SELECT discount FROM vouchers WHERE code = ?`, code).Scan(&d); err != nil {
			continue
		}
		out = append(out, AppliedVoucher{Code: code, Discount: d})
		total += d
	}
	return out, total
}

func splitCodes(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Add inserts/updates a cart line. Posted from product detail or catalog.
func (c *Cart) Add(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	productID, err := strconv.ParseInt(r.PostFormValue("product_id"), 10, 64)
	if err != nil || productID <= 0 {
		c.flash(r, "Bad product reference.")
		http.Redirect(w, r, "/catalog", http.StatusSeeOther)
		return
	}
	qty, err := strconv.Atoi(r.PostFormValue("qty"))
	if err != nil || qty <= 0 {
		qty = 1
	}

	// Look up the canonical product — we never trust client price/stock.
	var (
		slug  string
		stock int
	)
	err = c.DB.QueryRow(`SELECT slug, stock FROM products WHERE id = ?`, productID).Scan(&slug, &stock)
	if errors.Is(err, sql.ErrNoRows) {
		c.flash(r, "That item is not in the catalog.")
		http.Redirect(w, r, "/catalog", http.StatusSeeOther)
		return
	}
	if err != nil {
		log.Printf("cart add lookup: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if qty > stock {
		qty = stock
	}
	if qty <= 0 {
		c.flash(r, "Item out of stock.")
		http.Redirect(w, r, "/catalog/"+slug, http.StatusSeeOther)
		return
	}

	// Upsert: if the user already has this product in their cart, add to qty.
	const upsert = `
		INSERT INTO cart_items (user_id, product_id, qty) VALUES (?, ?, ?)
		ON CONFLICT(user_id, product_id) DO UPDATE SET qty = qty + excluded.qty
	`
	if _, err := c.DB.Exec(upsert, user.ID, productID, qty); err != nil {
		log.Printf("cart add upsert: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	c.flash(r, "Added to cart.")
	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

// Checkout processes POST /cart/checkout. PLANTED VULN a01-cart-price-tampering:
// per-line unit_price and qty arrive in hidden form fields and the server
// trusts them — a tampering crew member can pay less than the catalog asks.
// The created manifest reflects the client-supplied values; only an audit
// against the canonical DB price would catch the discrepancy.
func (c *Cart) Checkout(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	const q = `
		SELECT p.id, p.name, p.price, ci.qty
		FROM cart_items ci
		JOIN products p ON p.id = ci.product_id
		WHERE ci.user_id = ?
		ORDER BY ci.created_at
	`
	rows, err := c.DB.Query(q, user.ID)
	if err != nil {
		log.Printf("cart checkout query: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type canon struct {
		id        int64
		name      string
		realPrice int
		realQty   int
	}
	var lines []canon
	for rows.Next() {
		var l canon
		if err := rows.Scan(&l.id, &l.name, &l.realPrice, &l.realQty); err != nil {
			log.Printf("cart checkout scan: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		lines = append(lines, l)
	}
	if len(lines) == 0 {
		c.flash(r, "Cart is empty.")
		http.Redirect(w, r, "/cart", http.StatusSeeOther)
		return
	}

	// Build manifest items from client-submitted form values. No comparison
	// to the canonical price is performed here — that is the point.
	clientTotal := 0
	canonTotal := 0
	tampered := false
	items := make([]ManifestItem, 0, len(lines))
	for _, l := range lines {
		priceKey := fmt.Sprintf("unit_price_%d", l.id)
		qtyKey := fmt.Sprintf("qty_%d", l.id)
		unitPrice, perr := strconv.Atoi(r.PostFormValue(priceKey))
		if perr != nil {
			unitPrice = l.realPrice
		}
		qty, qerr := strconv.Atoi(r.PostFormValue(qtyKey))
		if qerr != nil || qty <= 0 {
			qty = l.realQty
		}
		items = append(items, ManifestItem{Name: l.name, Qty: qty, UnitPrice: unitPrice})
		clientTotal += unitPrice * qty
		canonTotal += l.realPrice * l.realQty
		if unitPrice < l.realPrice || qty < l.realQty {
			tampered = true
		}
	}

	_, discount := c.appliedVouchers(r)
	finalTotal := clientTotal - discount
	if finalTotal < 0 {
		finalTotal = 0
	}

	itemsJSON, err := json.Marshal(items)
	if err != nil {
		log.Printf("cart checkout marshal: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	summary := fmt.Sprintf("Commissary draw (%d line%s)", len(items), pluralS(len(items)))
	res, err := c.DB.Exec(
		`INSERT INTO manifests (user_id, summary, items_json, total_credits) VALUES (?, ?, ?, ?)`,
		user.ID, summary, string(itemsJSON), finalTotal,
	)
	if err != nil {
		log.Printf("cart checkout insert manifest: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := c.DB.Exec(`DELETE FROM cart_items WHERE user_id = ?`, user.ID); err != nil {
		log.Printf("cart checkout clear: %v", err)
	}
	c.Session.Remove(r.Context(), voucherSessionKey)

	if tampered || clientTotal < canonTotal {
		const flip = `
			UPDATE vulnerabilities
			SET status = 'discovered',
			    discovered_at = CURRENT_TIMESTAMP
			WHERE id = ? AND status = 'undiscovered'
		`
		if _, ferr := c.DB.Exec(flip, cartTamperTrackerID); ferr != nil {
			log.Printf("cart tamper discover flip: %v", ferr)
		}
	}

	mid, _ := res.LastInsertId()
	c.flash(r, fmt.Sprintf("Requisition filed. Manifest #%d.", mid))
	http.Redirect(w, r, fmt.Sprintf("/manifest/%d", mid), http.StatusSeeOther)
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// Remove deletes one cart line for the current user.
func (c *Cart) Remove(w http.ResponseWriter, r *http.Request) {
	user := requireLogin(w, r, c.Session)
	if user == nil {
		return
	}
	productID, err := strconv.ParseInt(r.PathValue("product_id"), 10, 64)
	if err != nil || productID <= 0 {
		http.Redirect(w, r, "/cart", http.StatusSeeOther)
		return
	}
	if _, err := c.DB.Exec(`DELETE FROM cart_items WHERE user_id = ? AND product_id = ?`, user.ID, productID); err != nil {
		log.Printf("cart remove: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	c.flash(r, "Removed from cart.")
	http.Redirect(w, r, "/cart", http.StatusSeeOther)
}

func (c *Cart) flash(r *http.Request, msg string) {
	c.Session.Put(r.Context(), session.KeyFlash, msg)
}

// trimMax shortens s to at most n characters (graceful, not exact bytes).
// Used by comms.go too — defined here for handler-package reach.
func trimMax(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
