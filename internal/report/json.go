package report

import (
	"encoding/json"
	"io"

	"github.com/jshultz/vulnscope/internal/scanner"
)

// SchemaVersion is bumped any time the JSON output shape changes in a way
// downstream consumers would care about. Treat it like an API version.
const SchemaVersion = "1.0.0"

type jsonEnvelope struct {
	Schema  string           `json:"schema"`
	Version string           `json:"schema_version"`
	Result  *scanner.Result  `json:"result"`
}

// JSON writes r to w as pretty-printed JSON with a stable envelope.
func JSON(w io.Writer, r *scanner.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(jsonEnvelope{
		Schema:  "vulnscope.scan-result",
		Version: SchemaVersion,
		Result:  r,
	})
}
