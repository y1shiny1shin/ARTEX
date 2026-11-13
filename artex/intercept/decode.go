package intercept

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Decoding is a deterministic, bounded pre-pass over the current tool arguments
// and script snapshots. It exists because a keyword/regex rule can be bypassed by
// base64/hex/url/gzip wrapping: the raw text contains none of the forbidden
// tokens, while the executed payload does. The decoded text is evidence for the
// rule layer and the LLM judge; it is never executed here.

const (
	maxDecodeSources    = 16
	maxDecodeSourceSize = 64 << 10 // 64 KiB per source
	maxDecodedPayloads  = 32
	maxDecodedBytes     = 64 << 10
	maxBase64Token      = 16 << 10
	minBase64Token      = 8
)

// DecodedPayload is one bounded decode result with provenance. Source tells the
// reviewer whether the text came from the tool arguments or a script snapshot.
type DecodedPayload struct {
	Source    string `json:"source"`
	Encoding  string `json:"encoding"`
	Text      string `json:"text"`
	Truncated bool   `json:"truncated,omitempty"`
}

var (
	reBase64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{8,}={0,2}`)
	reHexEscapes  = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){4,}`)
	reLongHex     = regexp.MustCompile(`\b(?:0x)?[0-9a-fA-F]{32,}\b`)
)

// DecodePayloads scans the supplied sources (tool arguments first, then script
// snapshots) and returns bounded decoded text. Ordering is stable, duplicates are
// dropped, and every source is capped so a large response cannot turn the review
// path into an unbounded decompressor.
func DecodePayloads(sources []string) []DecodedPayload {
	var out []DecodedPayload
	seen := map[string]bool{}
	add := func(source, encoding, text string, truncated bool) {
		if len(out) >= maxDecodedPayloads {
			return
		}
		text = strings.TrimSpace(text)
		if text == "" || !isUsefulDecodedText(text) {
			return
		}
		if len(text) > maxDecodedBytes {
			text = truncateUTF8(text, maxDecodedBytes)
			truncated = true
		}
		key := encoding + "\x00" + text
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, DecodedPayload{Source: source, Encoding: encoding, Text: text, Truncated: truncated})
	}

	for si, raw := range sources {
		if si >= maxDecodeSources || len(out) >= maxDecodedPayloads {
			break
		}
		source := "arguments"
		if si > 0 {
			source = "script"
		}
		s := raw
		truncatedSource := false
		if len(s) > maxDecodeSourceSize {
			s = truncateUTF8(s, maxDecodeSourceSize)
			truncatedSource = true
		}

		// Base64 / base64url tokens. Decode each candidate, then recursively look
		// for gzip/zlib inside the decoded bytes.
		for _, tok := range reBase64Token.FindAllString(s, 24) {
			if len(tok) < minBase64Token || len(tok) > maxBase64Token {
				continue
			}
			if b, ok := decodeBase64(tok); ok {
				if text, ok := textFromBytes(b); ok {
					add(source, "base64", text, truncatedSource)
				}
				for _, enc := range []string{"gzip", "zlib"} {
					if text, ok := decompressText(b, enc); ok {
						add(source, "base64+"+enc, text, truncatedSource)
					}
				}
			}
		}

		// Shell-style \xNN escapes.
		for _, tok := range reHexEscapes.FindAllString(s, 8) {
			if text, ok := decodeHexEscapes(tok); ok {
				add(source, "hex-escapes", text, truncatedSource)
			}
		}

		// Long hex blobs (32+ hex chars) are common in encoded webshell payloads.
		for _, tok := range reLongHex.FindAllString(s, 8) {
			tok = strings.TrimPrefix(strings.TrimPrefix(tok, "0x"), "0X")
			if len(tok)%2 != 0 {
				continue
			}
			if b, err := hex.DecodeString(tok); err == nil {
				if text, ok := textFromBytes(b); ok {
					add(source, "hex", text, truncatedSource)
				}
			}
		}

		// URL encoding is common in HTTP query strings and form bodies.
		if strings.Contains(s, "%") {
			if u, err := url.QueryUnescape(s); err == nil && u != s {
				add(source, "url", u, truncatedSource)
			}
		}
	}
	return out
}

func decodeBase64(tok string) ([]byte, bool) {
	if b, err := base64.StdEncoding.DecodeString(tok); err == nil && len(b) > 0 {
		return b, true
	}
	if b, err := base64.RawStdEncoding.DecodeString(tok); err == nil && len(b) > 0 {
		return b, true
	}
	if b, err := base64.URLEncoding.DecodeString(tok); err == nil && len(b) > 0 {
		return b, true
	}
	if b, err := base64.RawURLEncoding.DecodeString(tok); err == nil && len(b) > 0 {
		return b, true
	}
	return nil, false
}

func decodeHexEscapes(tok string) (string, bool) {
	var b strings.Builder
	for i := 0; i+3 < len(tok); i += 4 {
		if tok[i] != '\\' || tok[i+1] != 'x' {
			return "", false
		}
		v, ok := hexByte(tok[i+2], tok[i+3])
		if !ok {
			return "", false
		}
		b.WriteByte(v)
	}
	if b.Len() == 0 {
		return "", false
	}
	return b.String(), true
}

func hexByte(a, b byte) (byte, bool) {
	hi, ok1 := hexNibble(a)
	lo, ok2 := hexNibble(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return hi<<4 | lo, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

func decompressText(b []byte, kind string) (string, bool) {
	var r io.ReadCloser
	var err error
	switch kind {
	case "gzip":
		if len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
			return "", false
		}
		r, err = gzip.NewReader(bytes.NewReader(b))
	case "zlib":
		r, err = zlib.NewReader(bytes.NewReader(b))
	default:
		return "", false
	}
	if err != nil {
		return "", false
	}
	defer r.Close()
	limited := io.LimitReader(r, maxDecodedBytes+1)
	out, err := io.ReadAll(limited)
	if err != nil || len(out) == 0 {
		return "", false
	}
	return textFromBytes(out)
}

func textFromBytes(b []byte) (string, bool) {
	if len(b) == 0 || bytes.IndexByte(b, 0) >= 0 {
		return "", false
	}
	if !utf8.Valid(b) {
		return "", false
	}
	if !isUsefulDecodedText(string(b)) {
		return "", false
	}
	return string(b), true
}

// isUsefulDecodedText filters binary images and random identifier noise while
// keeping shell fragments, URLs, JSON, and natural-language payloads.
func isUsefulDecodedText(s string) bool {
	if len(s) < 4 {
		return false
	}
	total, printable, control := 0, 0, 0
	for _, r := range s {
		total++
		switch {
		case r == '\n' || r == '\r' || r == '\t':
			printable++
		case unicode.IsPrint(r):
			printable++
		case unicode.IsSpace(r):
			printable++
		default:
			control++
		}
	}
	if total == 0 || control*10 > total {
		return false
	}
	if printable*100 < total*85 {
		return false
	}
	// Require at least one structural character that scripts/URLs/JSON use. This
	// suppresses base64 of short random tokens while keeping real payloads.
	if !strings.ContainsAny(s, " \t\n;|&$(){}[]<>/\\'\"=:.,_-") && !strings.Contains(s, "://") {
		return false
	}
	return true
}

func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	end := limit
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	return s[:end]
}
