// Package views loads html/template files from views/ at the project root
// and renders pages that share a common layout.
//
// Convention: each page template defines a {{define "content"}} block;
// layout.html invokes {{template "content" .}} inside its body. We parse
// layout.html alongside each page template into its own *template.Template,
// keyed by page name (without ".html"). Calling Render(w, "tracker", data)
// executes the layout, which in turn pulls in tracker.html's content block.
//
// Auto-escaping via html/template guards against XSS by default — important
// for the scaffold's "defensive baseline" before any vulns are planted.
package views

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Views holds the parsed template sets, one per page.
type Views struct {
	pages map[string]*template.Template
}

// Load parses views/layout.html plus every other *.html in views/ into one
// template set per page.
func Load(dir string) (*Views, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	layoutPath := filepath.Join(dir, "layout.html")
	if _, err := os.Stat(layoutPath); err != nil {
		return nil, fmt.Errorf("missing layout.html in %s: %w", dir, err)
	}

	pages := make(map[string]*template.Template)
	for _, e := range entries {
		if e.IsDir() || e.Name() == "layout.html" || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		pagePath := filepath.Join(dir, e.Name())
		t, err := template.ParseFiles(layoutPath, pagePath)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", pagePath, err)
		}
		name := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		pages[name] = t
	}
	return &Views{pages: pages}, nil
}

// Render writes a fully-rendered page to w. name is the page template name
// without the ".html" suffix (e.g. "landing", "tracker"). data is the value
// passed as "." inside the templates.
func (v *Views) Render(w io.Writer, name string, data any) error {
	t, ok := v.pages[name]
	if !ok {
		return fmt.Errorf("views: no page %q", name)
	}
	return t.ExecuteTemplate(w, "layout.html", data)
}
