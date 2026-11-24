package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// offlineTrack pins a cluster, splits one validator 3 of 4 over its
// signers, drafts an import order for s2 (share index 2) and assembles it
// signed by two approvers. It returns the validator key, the signed order,
// the split file and s2's shares file (mode 0600, the 4-field form of
// split).
func offlineTrack(t *testing.T, fc *fakeCluster) (pk string, signed, splitPath, sharesFile string) {
	t.Helper()
	mustTool(t, "pin", "-cluster", fc.cluster)
	key, shares, splitPath := split(t, fc.dir, 3, 4, []string{"s1", "s2", "s3", "s4"})
	body := fc.path("import.bin")
	mustTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s2", "-split", splitPath, "-out", body)
	sigs := fc.signAll(t, body, 0, 1)
	signed = fc.path("import.signed")
	mustTool(t, "assemble", "-out", signed, body, sigs[0], sigs[1])
	sharePub, err := core.PubkeyOf(shares[1].Secret) // index 2 is s2's
	if err != nil {
		t.Fatal(err)
	}
	sharesFile = fc.path("s2-shares.txt")
	if err := os.WriteFile(sharesFile, fmt.Appendf(nil, "0x%x %s 2 %s\n", shares[1].Secret, key, sharePub), 0o600); err != nil {
		t.Fatal(err)
	}
	return key.String(), signed, splitPath, sharesFile
}

// The offline seal end to end: identity exports a verified identity, seal
// seals the shares offline to its import key, and import -sealed relays
// the frames without a plaintext share anywhere in between — in
// IMPORT_SHARES_SEALED batches to a runner that takes them, and one
// IMPORT_SHARE_SEALED per share to one that does not.
func TestOfflineSealRelay(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprint("batch ", batch), func(t *testing.T) {
			fc := newFakeCluster(t)
			if batch {
				fc.runners["s2"].ServeBatch()
			}
			_, signed, splitPath, sharesFile := offlineTrack(t, fc)
			out := mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", fc.path("s2.identity.json"))
			wantIn(t, out, "identity of s2 (verifier dev)", "wrote "+fc.path("s2.identity.json"))
			out = mustTool(t, "seal", "-identity", fc.path("s2.identity.json"), "-shares", sharesFile,
				"-order", signed, "-split", splitPath, "-out", fc.path("s2.sealed.json"))
			wantIn(t, out, "sealed 1 shares of s2 (verifier dev)", "ciphertext", "wrote "+fc.path("s2.sealed.json"))

			out = mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed,
				"-commitments", splitPath, "-sealed", fc.path("s2.sealed.json"))
			wantIn(t, out, "s2: relayed 1 sealed shares, skipped 0 held already")
			r := fc.runners["s2"]
			if keys := r.Keys(); len(keys) != 1 {
				t.Fatalf("runner holds %d keys, want 1", len(keys))
			}
			// The sealed frame carries the right share: its share pubkey is
			// the commitments' value at index 2 (the runner checks this
			// inside the TEE; here it checks the offline seal).
			var sf sealedFile
			if err := readStrictJSON(fc.path("s2.sealed.json"), &sf); err != nil {
				t.Fatal(err)
			}
			reqs, err := wireadmin.DecodeImportBatch(sf.Frames[0])
			if err != nil || len(reqs) != 1 {
				t.Fatalf("frame: %v, %d shares", err, len(reqs))
			}
			if want, err := threshold.FeldmanEval(reqs[0].Commitments, 2); err != nil || want != reqs[0].SharePubkey {
				t.Fatalf("frame share pubkey %s, want the commitments' value at 2 (%v)", reqs[0].SharePubkey, err)
			}
			batches, singles := 1, 1 // the probe, and one request per share
			if batch {
				batches, singles = 2, 0
			}
			if r.Seen(wireadmin.TypeImportBatch) != batches || r.Seen(wireadmin.TypeImportSealed) != singles {
				t.Fatalf("%d batch requests, %d single ones; want %d, %d",
					r.Seen(wireadmin.TypeImportBatch), r.Seen(wireadmin.TypeImportSealed), batches, singles)
			}
		})
	}
}

// seal refuses the identity of another signer before it reads the shares:
// the order names s2's setup, the identity is s3's. The relay refuses a
// file sealed for another signer, an order it was not sealed for, and
// -interchange with -sealed.
func TestOfflineSealRefusals(t *testing.T) {
	fc := newFakeCluster(t)
	_, signed, splitPath, sharesFile := offlineTrack(t, fc)
	ident2 := fc.path("s2.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident2)
	ident3 := fc.path("s3.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s3", "-out", ident3)

	// s3's identity with s2's order: refused before the shares are read.
	out := failTool(t, "seal", "-identity", ident3, "-shares", sharesFile, "-order", signed, "-split", splitPath, "-out", fc.path("x.json"))
	wantIn(t, out, "is an import order for setup", "the identity of s3 is of setup")

	// A tampered identity file, its import key changed: a cloud verifier
	// refuses it at the seal (the attestation's user data covers the key);
	// the dev verifier proves nothing, so there the tamper shows at the
	// relay, which checks the live import key against the sealed file's
	// fingerprint before anything is sent.
	var f identityFile
	if err := readStrictJSON(ident2, &f); err != nil {
		t.Fatal(err)
	}
	f.Identity.ImportKey[0] ^= 1
	if b, err := marshalFile(&f); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(fc.path("tampered.identity.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	mustTool(t, "seal", "-identity", fc.path("tampered.identity.json"), "-shares", sharesFile,
		"-order", signed, "-split", splitPath, "-out", fc.path("tampered.sealed.json"))
	out = failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed, "-commitments", splitPath,
		"-sealed", fc.path("tampered.sealed.json"))
	wantIn(t, out, "restarted since the file was sealed")

	// The real seal for the relay checks.
	sealed := fc.path("s2.sealed.json")
	mustTool(t, "seal", "-identity", ident2, "-shares", sharesFile, "-order", signed, "-split", splitPath, "-out", sealed)

	// Relay to another signer: each member runs its own setup, so the
	// order already refuses s3 before the file's signer is compared.
	out = failTool(t, "import", "-cluster", fc.cluster, "-signer", "s3", "-order", signed, "-commitments", splitPath, "-sealed", sealed)
	wantIn(t, out, "is an import order for setup", "s3 runs setup")
	// Another order: the same split drafted with another not_after, so
	// another hash.
	body2 := fc.path("import2.bin")
	mustTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s2", "-split", splitPath, "-not-after", "6h", "-out", body2)
	sigs2 := fc.signAll(t, body2, 0, 1)
	signed2 := fc.path("import2.signed")
	mustTool(t, "assemble", "-out", signed2, body2, sigs2[0], sigs2[1])
	out = failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed2, "-commitments", splitPath, "-sealed", sealed)
	wantIn(t, out, "sealed for order", "the relay's order is")
	// -interchange belongs to seal, not to the relay.
	out = failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed, "-commitments", splitPath,
		"-sealed", sealed, "-interchange", fc.path("ic.json"))
	wantIn(t, out, "usage")
}

// A sealed file for one runner boot goes nowhere else: the relay checks
// the live runner's import key against the file's fingerprint before
// anything is sent. A fingerprint of another boot (a runner that restarted
// since the seal, or a file sealed elsewhere) is refused with nothing
// sent.
func TestOfflineSealWrongBoot(t *testing.T) {
	fc := newFakeCluster(t)
	_, signed, splitPath, sharesFile := offlineTrack(t, fc)
	ident := fc.path("s2.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident)
	sealed := fc.path("s2.sealed.json")
	mustTool(t, "seal", "-identity", ident, "-shares", sharesFile, "-order", signed, "-split", splitPath, "-out", sealed)

	// Another boot's fingerprint in the file: the runner's own key did not
	// change, so this is exactly what a seal for another boot looks like
	// to the relay.
	var sf sealedFile
	if err := readStrictJSON(sealed, &sf); err != nil {
		t.Fatal(err)
	}
	sf.Identity.ImportKeySHA256 = strings.Repeat("0e", 32)
	if b, err := marshalFile(&sf); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(fc.path("otherboot.sealed.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	r := fc.runners["s2"]
	batches, singles := r.Seen(wireadmin.TypeImportBatch), r.Seen(wireadmin.TypeImportSealed)
	out := failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed, "-commitments", splitPath,
		"-sealed", fc.path("otherboot.sealed.json"))
	wantIn(t, out, "restarted since the file was sealed", "re-run signer-admin identity here and signer-admin seal on the dealer")
	if r.Seen(wireadmin.TypeImportBatch) != batches || r.Seen(wireadmin.TypeImportSealed) != singles {
		t.Fatal("the relay sent shares of a file for another boot")
	}
}

// The identity and sealed files decode strictly: an unknown field and a
// wrong version are refused.
func TestOfflineSealStrictFiles(t *testing.T) {
	fc := newFakeCluster(t)
	_, signed, splitPath, sharesFile := offlineTrack(t, fc)
	ident := fc.path("s2.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident)
	sealed := fc.path("s2.sealed.json")
	mustTool(t, "seal", "-identity", ident, "-shares", sharesFile, "-order", signed, "-split", splitPath, "-out", sealed)

	rewrite := func(path string, edit func(m map[string]json.RawMessage)) {
		t.Helper()
		var m map[string]json.RawMessage
		if err := json.Unmarshal(mustRead(t, path), &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rewrite(ident, func(m map[string]json.RawMessage) { m["extra"] = json.RawMessage("1") })
	if _, err := readIdentityFile(ident); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("identity file took an unknown field: %v", err)
	}
	rewrite(sealed, func(m map[string]json.RawMessage) { m["extra"] = json.RawMessage("1") })
	if _, err := readSealedFile(sealed); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("sealed file took an unknown field: %v", err)
	}
	rewrite(sealed, func(m map[string]json.RawMessage) { m["version"] = json.RawMessage("2") })
	if _, err := readSealedFile(sealed); err == nil {
		t.Fatal("sealed file took version 2")
	}
}

// A prod-chain runner takes no plaintext shares file: import refuses it
// before it dials, and the sealed path works on the same cluster.
func TestImportPlaintextRefusedOnProdChain(t *testing.T) {
	fc := newFakeClusterMainnet(t)
	_, signed, splitPath, sharesFile := offlineTrack(t, fc)
	seen := fc.runners["s2"].Seen(wire.TypeIdentity)
	out := failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-shares", sharesFile)
	wantIn(t, out, "s2 signs for a prod chain, which takes no plaintext shares file", "signer-admin seal", "-sealed")
	if fc.runners["s2"].Seen(wire.TypeIdentity) != seen {
		t.Fatal("the refused import reached the runner")
	}

	// The sealed path on the same cluster.
	ident := fc.path("s2.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident)
	sealed := fc.path("s2.sealed.json")
	mustTool(t, "seal", "-identity", ident, "-shares", sharesFile, "-order", signed, "-split", splitPath, "-out", sealed)
	out = mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed, "-commitments", splitPath, "-sealed", sealed)
	wantIn(t, out, "s2: relayed 1 sealed shares")
	if len(fc.runners["s2"].Keys()) != 1 {
		t.Fatalf("runner holds %d keys, want 1", len(fc.runners["s2"].Keys()))
	}
}

// seal bakes the interchange maxima into the sealed frames, as the online
// import does, and the relay takes the file.
func TestOfflineSealInterchange(t *testing.T) {
	fc := newFakeCluster(t)
	pk, signed, splitPath, sharesFile := offlineTrack(t, fc)
	ident := fc.path("s2.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident)
	// The identity file carries the setup's chain, so the interchange
	// file must name its genesis validators root.
	var f identityFile
	if err := readStrictJSON(ident, &f); err != nil {
		t.Fatal(err)
	}
	if f.Chain == nil {
		t.Fatal("identity file carries no chain")
	}
	root := strings.TrimPrefix(f.Chain.GenesisValidatorsRoot, "0x")
	ic := writeFile(t, fc.path("ic.json"), `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x`+
		root+`"},"data":[{"pubkey":"`+pk+`","signed_blocks":[],"signed_attestations":[{"source_epoch":"3","target_epoch":"4"}]}]}`)
	sealed := fc.path("s2.sealed.json")
	out := mustTool(t, "seal", "-identity", ident, "-shares", sharesFile, "-order", signed, "-split", splitPath,
		"-interchange", ic, "-out", sealed)
	wantIn(t, out, "source 3 target 4")
	var sf sealedFile
	if err := readStrictJSON(sealed, &sf); err != nil {
		t.Fatal(err)
	}
	reqs, err := wireadmin.DecodeImportBatch(sf.Frames[0])
	if err != nil || len(reqs) != 1 {
		t.Fatalf("frame: %v", err)
	}
	if w := reqs[0].Interchange; w == nil || !w.HasAttestation || w.SourceEpoch != 3 || w.TargetEpoch != 4 {
		t.Fatalf("interchange maxima %v, want source 3 target 4", reqs[0].Interchange)
	}
	// And the relay takes it.
	out = mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed, "-commitments", splitPath, "-sealed", sealed)
	wantIn(t, out, "s2: relayed 1 sealed shares")
}
