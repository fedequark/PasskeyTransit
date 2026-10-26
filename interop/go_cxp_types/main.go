package main

import (
	"encoding/json"
	"fmt"
	"os"

	cxp "github.com/nvinuesa/go-cxp"
)

func keysLost(input, output map[string]json.RawMessage, candidates []string) []string {
	lost := make([]string, 0)
	for _, name := range candidates {
		if _, present := input[name]; present {
			if _, preserved := output[name]; !preserved {
				lost = append(lost, name)
			}
		}
	}
	return lost
}

func roundTrip(raw json.RawMessage, value any) (map[string]json.RawMessage, map[string]json.RawMessage, error) {
	var input, output map[string]json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(raw, value); err != nil {
		return nil, nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, nil, err
	}
	if err := json.Unmarshal(encoded, &output); err != nil {
		return nil, nil, err
	}
	return input, output, nil
}

func main() {
	if len(os.Args) != 2 {
		panic("fixture path required")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var fixture map[string]json.RawMessage
	if err := json.Unmarshal(data, &fixture); err != nil {
		panic(err)
	}
	reqIn, reqOut, err := roundTrip(fixture["request"], &cxp.ExportRequest{})
	if err != nil {
		panic(err)
	}
	resIn, resOut, err := roundTrip(fixture["response"], &cxp.ExportResponse{})
	if err != nil {
		panic(err)
	}
	var wide map[string]any
	if err := json.Unmarshal(fixture["request"], &wide); err != nil {
		panic(err)
	}
	wide["version"] = 256
	wideJSON, err := json.Marshal(wide)
	if err != nil {
		panic(err)
	}
	var wideRequest cxp.ExportRequest
	wideError := json.Unmarshal(wideJSON, &wideRequest)
	report := map[string]any{
		"source_commit": "94659f317ac62470a149cb3ecb769ed5d03d18a1",
		"scope": "go-cxp open Go CXP type deserialization and serialization only",
		"request_parse": "PASS",
		"response_parse": "PASS",
		"request_fields_dropped_on_roundtrip": keysLost(reqIn, reqOut, []string{"archive", "mode"}),
		"response_fields_dropped_on_roundtrip": keysLost(resIn, resOut, []string{"archive"}),
		"draft_width_version_256_rejected": wideError != nil,
		"hpke_jwe_decryption": "NOT_EVALUABLE",
		"provider_interoperability": "NOT_EVALUABLE",
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(encoded))
}
