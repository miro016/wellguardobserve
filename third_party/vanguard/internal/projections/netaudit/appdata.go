package netaudit

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// tlsExtServerName is the TLS extension type for server_name (SNI).
const tlsExtServerName = 0

// clientHelloSNI extracts the server_name from a TLS ClientHello carried in a TCP
// payload, or "" when the payload is not a ClientHello or carries no SNI. It parses
// only the bounded handshake structure it needs and copies no payload beyond the
// host name, which is itself audit metadata (the application-level target of the
// connection), never secret material.
func clientHelloSNI(payload []byte) string {
	// TLS record header: type(1)=22 handshake, version(2), length(2).
	if len(payload) < 5 || payload[0] != 0x16 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(payload[3:5]))
	body := payload[5:]
	if recLen < len(body) {
		body = body[:recLen]
	}
	// Handshake header: type(1)=1 ClientHello, length(3).
	if len(body) < 4 || body[0] != 0x01 {
		return ""
	}
	hs := body[4:]
	// ClientHello: version(2) + random(32).
	if len(hs) < 34 {
		return ""
	}
	p := hs[34:]
	// session_id
	if len(p) < 1 {
		return ""
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return ""
	}
	p = p[sidLen:]
	// cipher_suites
	if len(p) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if len(p) < csLen {
		return ""
	}
	p = p[csLen:]
	// compression_methods
	if len(p) < 1 {
		return ""
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return ""
	}
	p = p[cmLen:]
	// extensions
	if len(p) < 2 {
		return ""
	}
	extTotal := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if extTotal < len(p) {
		p = p[:extTotal]
	}
	for len(p) >= 4 {
		extType := binary.BigEndian.Uint16(p[0:2])
		extLen := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if len(p) < extLen {
			return ""
		}
		ext := p[:extLen]
		p = p[extLen:]
		if extType != tlsExtServerName {
			continue
		}
		return parseServerNameList(ext)
	}
	return ""
}

// parseServerNameList returns the first host_name entry of a TLS server_name_list.
func parseServerNameList(ext []byte) string {
	// server_name_list length(2), then entries: type(1)=0 host_name, length(2), name.
	if len(ext) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	list := ext[2:]
	if listLen < len(list) {
		list = list[:listLen]
	}
	for len(list) >= 3 {
		nameType := list[0]
		nameLen := int(binary.BigEndian.Uint16(list[1:3]))
		list = list[3:]
		if len(list) < nameLen {
			return ""
		}
		name := list[:nameLen]
		list = list[nameLen:]
		if nameType == 0 && len(name) > 0 {
			return strings.ToLower(strings.TrimSuffix(string(name), "."))
		}
	}
	return ""
}

// httpMethods are the request methods that identify a plaintext HTTP request, so a
// TLS or binary payload is not mistaken for one.
var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT "),
}

// httpHost extracts the Host header of a plaintext HTTP request in a TCP payload,
// or "" when the payload is not an HTTP request. The Host names the application
// target of the connection and is audit metadata; no request path or body is read.
func httpHost(payload []byte) string {
	if len(payload) < 5 {
		return ""
	}
	isRequest := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(payload, m) {
			isRequest = true
			break
		}
	}
	if !isRequest {
		return ""
	}
	// Bound the scan to the header block.
	head := payload
	if i := bytes.Index(head, []byte("\r\n\r\n")); i >= 0 {
		head = head[:i]
	}
	const maxHead = 8 * 1024
	if len(head) > maxHead {
		head = head[:maxHead]
	}
	for line := range bytes.SplitSeq(head, []byte("\r\n")) {
		if len(line) < 6 {
			continue
		}
		key := line[:5]
		if strings.EqualFold(string(key), "host:") {
			host := strings.TrimSpace(string(line[5:]))
			if h, _, ok := strings.Cut(host, ":"); ok {
				host = h
			}
			return strings.ToLower(strings.TrimSuffix(host, "."))
		}
	}
	return ""
}
