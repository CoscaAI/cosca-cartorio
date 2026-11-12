package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newLine builds a canonical, correctly signed anchor line. The signature is
// produced in the test, so no fixture and no network are involved.
func newLine(t *testing.T, priv ed25519.PrivateKey, seq int, prev string) anchorLine {
	t.Helper()
	a := anchorLine{
		V:          ledgerVersion,
		Seq:        seq,
		Prev:       prev,
		Upto:       10 * seq,
		Head:       strings.Repeat(fmt.Sprintf("%02x", seq), 32),
		MerkleRoot: strings.Repeat(fmt.Sprintf("%02x", seq+100), 32),
		TS:         "2026-11-12T00:00:00Z",
	}
	h, err := a.anchorHash()
	if err != nil {
		t.Fatalf("anchorHash: %v", err)
	}
	a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(h)))
	return a
}

// newLineAt builds a canonical, signed line with an explicit upto and root, so a
// test can name the pre-checkpoint window exactly instead of deriving it.
func newLineAt(t *testing.T, priv ed25519.PrivateKey, seq int, prev string, upto int, root string) anchorLine {
	t.Helper()
	a := anchorLine{
		V:          ledgerVersion,
		Seq:        seq,
		Prev:       prev,
		Upto:       upto,
		Head:       strings.Repeat(fmt.Sprintf("%02x", seq), 32),
		MerkleRoot: root,
		TS:         "2026-11-12T00:00:00Z",
	}
	h, err := a.anchorHash()
	if err != nil {
		t.Fatalf("anchorHash: %v", err)
	}
	a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(h)))
	return a
}

func hashOf(t *testing.T, a anchorLine) string {
	t.Helper()
	h, err := a.anchorHash()
	if err != nil {
		t.Fatalf("anchorHash: %v", err)
	}
	return h
}

// encode serialises lines exactly as the emitter does: json.Marshal plus "\n".
func encode(t *testing.T, lines ...anchorLine) []byte {
	t.Helper()
	var b strings.Builder
	for _, a := range lines {
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// TestCanonicalBytes pins the field order and the omitempty sig. Reordering the
// struct would silently invalidate every anchor ever published.
func TestCanonicalBytes(t *testing.T) {
	a := anchorLine{
		V:          ledgerVersion,
		Seq:        1,
		Prev:       zeroHash,
		Upto:       7,
		Head:       strings.Repeat("a", 64),
		MerkleRoot: strings.Repeat("b", 64),
		TS:         "2026-01-02T03:04:05Z",
		Sig:        "ignorada-pelo-hash",
	}
	got, err := a.canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := fmt.Sprintf(`{"v":2,"seq":1,"prev":%q,"upto":7,"head":%q,"merkle_root":%q,"ts":"2026-01-02T03:04:05Z"}`,
		zeroHash, a.Head, a.MerkleRoot)
	if string(got) != want {
		t.Fatalf("bytes canônicos mudaram:\n obtido: %s\nquerido: %s", got, want)
	}
	if strings.Contains(string(got), "sig") {
		t.Fatalf("sig não pode entrar no canônico: %s", got)
	}
}

func TestLoadPubKeyDirectBase64(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	got, err := loadPubKey(base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatalf("loadPubKey(base64 direto): %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatalf("chave lida difere da gerada")
	}
}

// TestRun is the table of verdicts. Every failure case also asserts that no
// partial INTEGRO line was printed.
func TestRun(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	_, foreignPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	line1 := newLine(t, priv, 1, zeroHash)
	line2 := newLine(t, priv, 2, hashOf(t, line1))
	line3 := newLine(t, priv, 3, hashOf(t, line2))

	// (e) one flipped byte inside the signature; the canonical bytes, and so the
	// hash, stay untouched.
	tamperedSig := line1
	rawSig, err := base64.StdEncoding.DecodeString(tamperedSig.Sig)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	rawSig[0] ^= 0x01
	tamperedSig.Sig = base64.StdEncoding.EncodeToString(rawSig)

	// (c) numbering with a hole: seq 3 where 2 was expected.
	wrongSeq := line2
	wrongSeq.Seq = 3

	// (d) prev pointing back to the zero hash instead of the previous line.
	brokenPrev := line2
	brokenPrev.Prev = zeroHash

	// (f) head that is not 64 hex characters.
	badHead := line1
	badHead.Head = "not-a-64-hex-string"

	// Signature made by a different identity.
	foreign := newLine(t, foreignPriv, 1, zeroHash)

	// (g) the pre-checkpoint window: before the first checkpoint there is no
	// merkle root to commit to, so an explicit empty root is honest — but only
	// while 0 < upto < 32. Everything outside that window still demands 64 hex.
	genesisEmpty := newLineAt(t, priv, 1, zeroHash, 1, "")
	genesisUnsigned := genesisEmpty
	genesisUnsigned.Sig = ""
	emptyAt32 := newLineAt(t, priv, 1, zeroHash, 32, "")
	emptyAt0 := newLineAt(t, priv, 1, zeroHash, 0, "")
	emptyAt33 := newLineAt(t, priv, 1, zeroHash, 33, "")
	rootAt40 := newLineAt(t, priv, 1, zeroHash, 40, strings.Repeat("a", 64))
	root63At40 := newLineAt(t, priv, 1, zeroHash, 40, strings.Repeat("a", 63))

	good := encode(t, line1)
	dupKey := []byte(strings.Replace(string(good), `{"v":2,`, `{"v":3,"v":2,`, 1))
	unknownField := []byte(strings.Replace(string(good), `{"v":2,`, `{"v":2,"x":1,`, 1))

	tests := []struct {
		name       string
		content    []byte
		noFile     bool
		wantExit   int
		wantStdout string
		wantStderr string
	}{
		{name: "cartório vazio falha", content: nil, wantExit: 1, wantStderr: "cartório vazio"},
		{name: "só linhas em branco falha", content: []byte("\n\n"), wantExit: 1, wantStderr: "cartório vazio"},
		{name: "arquivo ausente falha", noFile: true, wantExit: 1, wantStderr: "cartório vazio"},
		{
			name:       "âncora válida de 1 linha passa",
			content:    good,
			wantExit:   0,
			wantStdout: fmt.Sprintf("anchors=1 head=%s upto=10 verdict=INTEGRO", line1.Head),
		},
		{
			name:       "cadeia de 3 âncoras passa",
			content:    encode(t, line1, line2, line3),
			wantExit:   0,
			wantStdout: fmt.Sprintf("anchors=3 head=%s upto=30 verdict=INTEGRO", line3.Head),
		},
		{name: "seq fora de ordem falha", content: encode(t, line1, wrongSeq), wantExit: 1, wantStderr: "numeração fora de ordem"},
		{name: "prev quebrado falha", content: encode(t, line1, brokenPrev), wantExit: 1, wantStderr: "prev não encadeia"},
		{name: "assinatura com 1 byte trocado falha", content: encode(t, tamperedSig), wantExit: 1, wantStderr: "assinatura não confere"},
		{name: "assinatura de outra chave falha", content: encode(t, foreign), wantExit: 1, wantStderr: "assinatura não confere"},
		{name: "head que não é hex de 64 falha", content: encode(t, badHead), wantExit: 1, wantStderr: "head não é hex de 64"},
		{
			name:       "âncora gênesis com merkle_root vazio passa",
			content:    encode(t, genesisEmpty),
			wantExit:   0,
			wantStdout: fmt.Sprintf("anchors=1 head=%s upto=1 verdict=INTEGRO", genesisEmpty.Head),
		},
		{name: "gênesis sem assinatura falha", content: encode(t, genesisUnsigned), wantExit: 1, wantStderr: "sem assinatura"},
		{name: "merkle_root vazio em upto=32 falha", content: encode(t, emptyAt32), wantExit: 1, wantStderr: "merkle_root inválido para upto=32"},
		{name: "merkle_root vazio em upto=0 falha", content: encode(t, emptyAt0), wantExit: 1, wantStderr: "merkle_root inválido para upto=0"},
		{name: "merkle_root vazio em upto=33 falha", content: encode(t, emptyAt33), wantExit: 1, wantStderr: "merkle_root inválido para upto=33"},
		{
			name:       "merkle_root de 64 hex em upto=40 passa",
			content:    encode(t, rootAt40),
			wantExit:   0,
			wantStdout: fmt.Sprintf("anchors=1 head=%s upto=40 verdict=INTEGRO", rootAt40.Head),
		},
		{name: "merkle_root de 63 hex em upto=40 falha", content: encode(t, root63At40), wantExit: 1, wantStderr: "merkle_root inválido para upto=40"},
		{name: "chave duplicada falha", content: dupKey, wantExit: 1, wantStderr: "forma canônica"},
		{name: "campo desconhecido falha", content: unknownField, wantExit: 1, wantStderr: "campo desconhecido"},
		{name: "JSON inválido falha", content: []byte("{nao-e-json}\n"), wantExit: 1, wantStderr: "JSON inválido"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, anchorsFileName)
			if !tc.noFile {
				if err := os.WriteFile(path, tc.content, 0o600); err != nil {
					t.Fatalf("WriteFile: %v", err)
				}
			}
			pubPath := filepath.Join(dir, pubFileName)
			key := base64.StdEncoding.EncodeToString(pub) + "\n"
			if err := os.WriteFile(pubPath, []byte(key), 0o600); err != nil {
				t.Fatalf("WriteFile pubkey: %v", err)
			}

			var stdout, stderr bytes.Buffer
			if got := run(path, pubPath, &stdout, &stderr); got != tc.wantExit {
				t.Fatalf("exit = %d, querido %d (stderr=%q)", got, tc.wantExit, stderr.String())
			}
			if tc.wantStdout != "" && !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Fatalf("stdout = %q, deve conter %q", stdout.String(), tc.wantStdout)
			}
			if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Fatalf("stderr = %q, deve conter %q", stderr.String(), tc.wantStderr)
			}
			if tc.wantExit != 0 {
				if strings.Contains(stdout.String(), "INTEGRO") {
					t.Fatalf("falha não pode imprimir INTEGRO: %q", stdout.String())
				}
				if stdout.Len() != 0 {
					t.Fatalf("falha não deve escrever em stdout: %q", stdout.String())
				}
			}
		})
	}
}

// TestShippedPubKey guards the published key file: it must stay a single valid
// Ed25519 public key, otherwise the whole cartório becomes unverifiable.
func TestShippedPubKey(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", pubFileName))
	if err != nil {
		t.Fatalf("pubkey publicada ilegível: %v", err)
	}
	pub, err := parsePubBytes(raw)
	if err != nil {
		t.Fatalf("pubkey publicada inválida: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pubkey publicada com %d bytes", len(pub))
	}
}
