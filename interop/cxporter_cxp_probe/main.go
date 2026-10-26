// Run the pinned cxporter exporter on a synthetic CXF document supplied by
// PasskeyTransit. This adapter is copied into cxporter's module at run time so
// that Go's internal-package boundary remains intact.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/nvinuesa/cxporter/internal/cxp"
	"github.com/nvinuesa/go-cxf"
)

type request struct {
	RecipientPublicKey string          `json:"recipientPublicKey"`
	CXF                json.RawMessage `json:"cxf"`
}

func run() error {
	var input request
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20))
	if err := decoder.Decode(&input); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	key, err := base64.RawURLEncoding.DecodeString(input.RecipientPublicKey)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("recipient public key must be 32 base64url-decoded bytes")
	}
	var header cxf.Header
	if err := json.Unmarshal(input.CXF, &header); err != nil {
		return fmt.Errorf("decode CXF: %w", err)
	}
	response, err := cxp.ExportResponse(&header, key)
	if err != nil {
		return fmt.Errorf("export response: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(response)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
