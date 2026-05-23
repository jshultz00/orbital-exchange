package handlers

import (
	"database/sql"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/alexedwards/scs/v2"

	"github.com/jshultz00/orbital-exchange/internal/session"
	"github.com/jshultz00/orbital-exchange/internal/views"
)

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

	data := pageData(r, c.Session, "Cart")
	data["Lines"] = lines
	data["Total"] = total
	render(w, c.Views, "cart", data)
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
