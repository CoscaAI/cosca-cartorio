// Command verify checks a cartório anchor log (anchors.jsonl) on its own, with
// no ledger, no memory block and no secret present.
//
// It is a SECOND, INDEPENDENT implementation of the anchor format emitted by
// `cadeia anchor`. That is deliberate: two implementations reading the same
// bytes must agree. If they ever disagree, the disagreement is the bug.
//
// One JSON object per line. The canonical bytes are json.Marshal of the struct
// with Sig blanked, so the omitempty sig field disappears from the payload:
//
//	{"v":2,"seq":1,"prev":"<64 hex>","upto":10,"head":"<64 hex>",
//	 "merkle_root":"<64 hex>","ts":"<RFC3339Nano>","sig":"<base64>"}
//
// merkle_root is a 64-hex root once the ledger has reached its first checkpoint
// (upto >= 32). Before that there is no root to commit to, so the field is
// present and explicitly empty — legal only while 0 < upto < 32.
//
//	hash(line)   = BLAKE3(canonical(line)), lowercase hex
//	prev(line N) = hash(line N-1); the first line has prev = 64 zeros
//	sig          = Ed25519 over the ASCII bytes of hash(line), standard base64
//
// Fail-closed: an empty log, a broken chain, a bad signature or a malformed
// line exits 1. The only success output is a single verdict=INTEGRO line.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/zeebo/blake3"
)

const (
	ledgerVersion   = 2
	hashHexLen      = 64
	anchorsFileName = "anchors.jsonl"
	pubFileName     = "pubkey.txt"
	// checkpointEvery is the checkpoint interval of Cadeia v2: a merkle root is
	// signed every 32 entries. The value is duplicated on purpose — the cartório
	// shares no code with the emitter, so an independent reader has to state the
	// same rule in its own words. Below the first checkpoint there is no root to
	// commit to, so an empty merkle_root is legal only inside that window.
	checkpointEvery = 32
)

// zeroHash is the prev expected on the first anchor line.
var zeroHash = strings.Repeat("0", hashHexLen)

// anchorLine is one line of anchors.jsonl. Field order IS the canonical order:
// never reorder, never rename, never decode into a map (Go randomises map order
// and every historical hash would break).
type anchorLine struct {
	V          int    `json:"v"`
	Seq        int    `json:"seq"`
	Prev       string `json:"prev"`
	Upto       int    `json:"upto"`
	Head       string `json:"head"`
	MerkleRoot string `json:"merkle_root"`
	TS         string `json:"ts"`
	Sig        string `json:"sig,omitempty"`
}

// canonical returns the exact bytes the emitter hashed and signed: the line
// with sig blanked, so hash and signature cover the same payload.
func (a anchorLine) canonical() ([]byte, error) {
	c := a
	c.Sig = ""
	return json.Marshal(c)
}

// anchorHash is the BLAKE3 hex of the line. It is both the value the signature
// covers and the prev of the next line.
func (a anchorLine) anchorHash() (string, error) {
	canon, err := a.canonical()
	if err != nil {
		return "", fmt.Errorf("canonicalização falhou: %w", err)
	}
	return blake3Hex(canon), nil
}

func blake3Hex(data []byte) string {
	sum := blake3.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// isHex64 reports whether s is exactly 64 hexadecimal characters.
func isHex64(s string) bool {
	if len(s) != hashHexLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// merkleRootOK reports whether the root is acceptable for an anchor covering
// upto entries. Before the first checkpoint there is no root to commit to, so an
// empty value is honest — but only inside that window, so a corrupted or missing
// root on a checkpointed ledger is still a failure. Accepting empty anywhere
// would let a wiped root pass as a young ledger.
func merkleRootOK(upto int, root string) bool {
	if root == "" {
		return upto > 0 && upto < checkpointEvery
	}
	return isHex64(root)
}

// b64decode accepts padded or raw standard base64, like the emitter does.
func b64decode(s string) ([]byte, error) {
	if raw, err := base64.StdEncoding.DecodeString(s); err == nil {
		return raw, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// decodeLine rejects anything the emitter would never write: unknown fields,
// duplicate keys and trailing garbage after the object.
func decodeLine(s string) (anchorLine, error) {
	var a anchorLine
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "json: unknown field ") {
			return a, fmt.Errorf("campo desconhecido %s", strings.TrimPrefix(msg, "json: unknown field "))
		}
		return a, fmt.Errorf("JSON inválido: %v", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return a, fmt.Errorf("conteúdo extra após o objeto JSON")
	}
	return a, nil
}

// parseAnchors reads every non-empty line. A malformed line is a problem, never
// a silent skip: the cartório either reads whole or it does not read.
func parseAnchors(raw []byte) ([]anchorLine, []string) {
	var lines []anchorLine
	var problems []string
	for i, text := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(text)
		if s == "" {
			continue
		}
		a, err := decodeLine(s)
		if err != nil {
			problems = append(problems, fmt.Sprintf("linha %d: %v", i+1, err))
			continue
		}
		// Strict canonical form: the bytes on disk must be exactly what the
		// emitter writes. This catches a duplicated key (last one wins on
		// decode) that would otherwise let two readers see two different lines.
		if canon, cerr := json.Marshal(a); cerr != nil || string(canon) != s {
			problems = append(problems, fmt.Sprintf("linha %d: fora da forma canônica (campo extra, chave duplicada, espaço ou ordem diferente)", i+1))
			continue
		}
		lines = append(lines, a)
	}
	return lines, problems
}

// report is the outcome of a full pass over the anchor log.
type report struct {
	anchors  int
	head     string
	upto     int
	problems []string
}

// verifyAnchors validates numbering, the prev chain and every signature. A line
// counts as good only when all of its checks pass.
func verifyAnchors(lines []anchorLine, pub ed25519.PublicKey) report {
	rep := report{problems: make([]string, 0, 4)}
	prev := zeroHash
	for i := range lines {
		a := &lines[i]
		where := fmt.Sprintf("âncora seq=%d (linha %d)", a.Seq, i+1)
		good := true
		bad := func(format string, args ...any) {
			rep.problems = append(rep.problems, where+": "+fmt.Sprintf(format, args...))
			good = false
		}
		if a.V != ledgerVersion {
			bad("versão %d desconhecida (esperado %d)", a.V, ledgerVersion)
		}
		if a.Seq != i+1 {
			bad("numeração fora de ordem (esperado %d)", i+1)
		}
		if !strings.EqualFold(a.Prev, prev) {
			bad("prev não encadeia (esperado %s, obtido %q)", short(prev), short(a.Prev))
		}
		if !isHex64(a.Head) {
			bad("head não é hex de %d caracteres", hashHexLen)
		}
		if !merkleRootOK(a.Upto, a.MerkleRoot) {
			bad("merkle_root inválido para upto=%d (vazio só é aceito em 0 < upto < %d, e hex de %d caso contrário)", a.Upto, checkpointEvery, hashHexLen)
		}
		if a.Upto <= 0 {
			bad("upto=%d inválido", a.Upto)
		}
		h, err := a.anchorHash()
		if err != nil {
			bad("%v", err)
			break // without a hash the chain cannot be followed any further
		}
		if a.Sig == "" {
			bad("sem assinatura")
		} else if verr := verifySig(pub, h, a.Sig); verr != nil {
			bad("%v", verr)
		}
		if good {
			rep.anchors++
		}
		prev = h
	}
	last := lines[len(lines)-1]
	rep.head, rep.upto = last.Head, last.Upto
	return rep
}

// verifySig checks one signature over the ASCII bytes of the hash hex string.
func verifySig(pub ed25519.PublicKey, hashHex, sigB64 string) error {
	raw, err := b64decode(sigB64)
	if err != nil {
		return fmt.Errorf("assinatura não é base64 válido")
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("assinatura com %d bytes (esperado %d)", len(raw), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, []byte(hashHex), raw) {
		return fmt.Errorf("assinatura não confere com a chave pública")
	}
	return nil
}

// loadPubKey accepts a readable file (base64, hex or raw 32 bytes) or the
// base64 text itself, mirroring `cadeia --pub`.
func loadPubKey(spec string) (ed25519.PublicKey, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, fmt.Errorf("chave pública vazia")
	}
	if raw, err := os.ReadFile(spec); err == nil {
		return parsePubBytes(raw)
	}
	b, err := b64decode(spec)
	if err != nil {
		return nil, fmt.Errorf("%q não é arquivo legível nem base64 válido", spec)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("chave pública com %d bytes (esperado %d)", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func parsePubBytes(raw []byte) (ed25519.PublicKey, error) {
	text := strings.TrimSpace(string(raw))
	if b, err := b64decode(text); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if b, err := hex.DecodeString(text); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), raw...)), nil
	}
	return nil, fmt.Errorf("arquivo de chave pública não contém 32 bytes (base64, hex ou bruto)")
}

// short truncates a hash for a readable message.
func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}

// run is main without the process exit, so tests can drive it.
func run(file, pubSpec string, stdout, stderr io.Writer) int {
	fail := func(format string, args ...any) int {
		fmt.Fprintf(stderr, "erro: "+format+"\n", args...)
		return 1
	}
	pub, err := loadPubKey(pubSpec)
	if err != nil {
		return fail("chave pública: %v", err)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return fail("cartório vazio: nenhuma âncora (%s ausente)", file)
		}
		return fail("não foi possível ler %s: %v", file, err)
	}
	lines, parseProblems := parseAnchors(raw)
	if len(parseProblems) > 0 {
		for _, p := range parseProblems {
			fmt.Fprintf(stderr, "problema: %s\n", p)
		}
		return fail("%s: %d linha(s) inválida(s)", file, len(parseProblems))
	}
	if len(lines) == 0 {
		return fail("cartório vazio: nenhuma âncora em %s", file)
	}

	rep := verifyAnchors(lines, pub)
	for _, p := range rep.problems {
		fmt.Fprintf(stderr, "problema: %s\n", p)
	}
	if len(rep.problems) > 0 || rep.anchors != len(lines) {
		return fail("verificação reprovada: %d de %d âncora(s) íntegra(s)", rep.anchors, len(lines))
	}
	fmt.Fprintf(stdout, "anchors=%d head=%s upto=%d verdict=INTEGRO\n", rep.anchors, rep.head, rep.upto)
	return 0
}

func main() {
	file := flag.String("file", anchorsFileName, "caminho do anchors.jsonl a verificar")
	pubSpec := flag.String("pub", pubFileName, "chave pública Ed25519 (arquivo ou base64)")
	flag.Parse()
	os.Exit(run(*file, *pubSpec, os.Stdout, os.Stderr))
}
