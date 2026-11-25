package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/importorder"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
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
// file sealed for another signer and -interchange with -sealed; a file
// goes under another order than the one it was sealed for when that order
// takes every share of it, and says so.
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
	// another hash. It takes every share of the file, which goes under it;
	// the relay says which order it used.
	body2 := fc.path("import2.bin")
	mustTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s2", "-split", splitPath, "-not-after", "6h", "-out", body2)
	sigs2 := fc.signAll(t, body2, 0, 1)
	signed2 := fc.path("import2.signed")
	mustTool(t, "assemble", "-out", signed2, body2, sigs2[0], sigs2[1])
	out = mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed2, "-commitments", splitPath, "-sealed", sealed)
	wantIn(t, out, "NOTICE s2: sealed for order "+fullHex(sha256.Sum256(mustRead(t, signed)))+
		", relayed under order "+fullHex(sha256.Sum256(mustRead(t, signed2))), "s2: relayed 1 sealed shares")
	if keys := fc.runners["s2"].Keys(); len(keys) != 1 {
		t.Fatalf("runner holds %d keys, want 1", len(keys))
	}
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

// secondSplit splits another key as the order track's split (the same t
// and n) into dir, and writes s2's shares file of it in the 4-field form
// of split. It returns the key, the split file and the shares file.
func secondSplit(t *testing.T, fc *fakeCluster, dir string) (key, splitPath, sharesFile string) {
	t.Helper()
	k, shares, splitPath := split(t, dir, 3, 4, []string{"s1", "s2", "s3", "s4"})
	sharePub, err := core.PubkeyOf(shares[1].Secret)
	if err != nil {
		t.Fatal(err)
	}
	sharesFile = fc.path("s2-shares-" + filepath.Base(dir) + ".txt")
	if err := os.WriteFile(sharesFile, fmt.Appendf(nil, "0x%x %s 2 %s\n", shares[1].Secret, k.String(), sharePub), 0o600); err != nil {
		t.Fatal(err)
	}
	return k.String(), splitPath, sharesFile
}

// orderFor drafts the order of splitPath for s2 and assembles it signed by
// two approvers.
func orderFor(t *testing.T, fc *fakeCluster, name, splitPath string) string {
	t.Helper()
	body := fc.path(name + ".bin")
	mustTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s2", "-split", splitPath, "-out", body)
	signed := fc.path(name + ".signed")
	mustTool(t, append([]string{"assemble", "-out", signed, body}, fc.signAll(t, body, 0, 1)...)...)
	return signed
}

// seal without -order seals the shares for the signer's share index of the
// split, and the file waits for its order: import -sealed attaches the
// order the approvers signed for the split, in a batch and one by one.
// With no order named, with another split file, or with an order of
// another split, nothing is sent.
func TestSealWithoutOrder(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprint("batch ", batch), func(t *testing.T) {
			fc := newFakeCluster(t)
			if batch {
				fc.runners["s2"].ServeBatch()
			}
			mustTool(t, "pin", "-cluster", fc.cluster) // import-draft reads the locked values in force
			key, shares, splitPath := split(t, fc.dir, 3, 4, []string{"s1", "s2", "s3", "s4"})
			sharePub, err := core.PubkeyOf(shares[1].Secret)
			if err != nil {
				t.Fatal(err)
			}
			sharesFile := fc.path("s2-shares.txt")
			if err := os.WriteFile(sharesFile, fmt.Appendf(nil, "0x%x %s 2 %s\n", shares[1].Secret, key.String(), sharePub), 0o600); err != nil {
				t.Fatal(err)
			}
			ident := fc.path("s2.identity.json")
			mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident)
			sealed := fc.path("s2.sealed.json")
			out := mustTool(t, "seal", "-identity", ident, "-shares", sharesFile, "-split", splitPath, "-out", sealed)
			wantIn(t, out, "sealed 1 shares of s2 (verifier dev)", "3 of 4, share index 2, no import order yet", "wrote "+sealed)

			// The file names the split and no order; its frame carries the
			// share without an order and without the split.
			var sf sealedFile
			if err := readStrictJSON(sealed, &sf); err != nil {
				t.Fatal(err)
			}
			if sf.OrderSHA256 != "" || sf.SplitSHA256 != fullHex(sha256.Sum256(mustRead(t, splitPath))) || sf.T != 3 || sf.N != 4 || sf.ShareIndex != 2 {
				t.Fatalf("the file names order %q, split %s, %d of %d, share index %d; want no order, the split's hash, 3 of 4, index 2",
					sf.OrderSHA256, sf.SplitSHA256, sf.T, sf.N, sf.ShareIndex)
			}
			reqs, err := wireadmin.DecodeImportBatch(sf.Frames[0])
			if err != nil || len(reqs) != 1 {
				t.Fatalf("frame: %v, %d shares", err, len(reqs))
			}
			if reqs[0].T != 0 || len(reqs[0].Order) != 0 || len(reqs[0].Commitments) != 0 {
				t.Fatalf("the frame carries a split or an order: t %d, %d order bytes, %d commitments",
					reqs[0].T, len(reqs[0].Order), len(reqs[0].Commitments))
			}

			r := fc.runners["s2"]
			sent := func() int { return r.Seen(wireadmin.TypeImportBatch) + r.Seen(wireadmin.TypeImportSealed) }
			before := sent()
			out = failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-sealed", sealed)
			wantIn(t, out, "sealed without an import order", "-order", "-commitments")
			// Another split file than the one the shares were sealed for.
			_, split2, _ := secondSplit(t, fc, fc.path("other"))
			signed2 := orderFor(t, fc, "import-other", split2)
			out = failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed2, "-commitments", split2, "-sealed", sealed)
			wantIn(t, out, "sealed for split", split2)
			// An order of another split: the same t, n and share index.
			out = failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed2, "-commitments", splitPath, "-sealed", sealed)
			wantIn(t, out, "does not name validator "+key.String(), "import-draft -split", "nothing sent")
			if sent() != before {
				t.Fatalf("the relay sent %d frames of a file without an order that takes it", sent()-before)
			}

			// The order of the split takes the shares: attached, and the
			// runner holds the share of index 2.
			signed := orderFor(t, fc, "import", splitPath)
			out = mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed, "-commitments", splitPath, "-sealed", sealed)
			wantIn(t, out, "s2: relayed 1 sealed shares, skipped 0 held already")
			if strings.Contains(out, "NOTICE") {
				t.Fatalf("the relay reports another order than the file's:\n%s", out)
			}
			keys := r.Keys()
			if len(keys) != 1 || keys[0].Pubkey.String() != key.String() || keys[0].SharePubkey != sharePub {
				t.Fatalf("runner holds %v; want share 2 of %s", keys, key)
			}
		})
	}
}

// seal with neither -order nor -split is the seal for a runner without a
// setup, as before: the file names no order, no split and no share index,
// and the relay sends it as it is.
func TestSealWithoutOrderOrSplit(t *testing.T) {
	fc := newFakeCluster(t)
	_, _, _, sharesFile := offlineTrack(t, fc)
	ident := fc.path("s2.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident)
	sealed := fc.path("s2.sealed.json")
	out := mustTool(t, "seal", "-identity", ident, "-shares", sharesFile, "-out", sealed)
	wantIn(t, out, "sealed 1 shares of s2 (verifier dev)", "wrote "+sealed)
	var sf sealedFile
	if err := readStrictJSON(sealed, &sf); err != nil {
		t.Fatal(err)
	}
	if sf.OrderSHA256 != "" || sf.SplitSHA256 != "" || sf.T != 0 || sf.N != 0 || sf.ShareIndex != 0 {
		t.Fatalf("the file names an order, a split or a share index: order %q, split %q, %d of %d, index %d",
			sf.OrderSHA256, sf.SplitSHA256, sf.T, sf.N, sf.ShareIndex)
	}
	out = mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-sealed", sealed)
	wantIn(t, out, "s2: relayed 1 sealed shares")
}

// seal with -order refuses an order that does not take the shares, with
// nothing written: one drafted from another split of another key, and one
// drafted from another split of the same key. Both have the t, n and share
// index of the order, which is all the seal compared before.
func TestSealOrderOfAnotherSplit(t *testing.T) {
	fc := newFakeCluster(t)
	_, signed, _, _ := offlineTrack(t, fc)
	ident := fc.path("s2.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident)
	sealed := fc.path("s2.sealed.json")

	// Another key, split the same way.
	_, split2, shares2 := secondSplit(t, fc, fc.path("other"))
	out := failTool(t, "seal", "-identity", ident, "-shares", shares2, "-order", signed, "-split", split2, "-out", sealed)
	wantIn(t, out, "the import order does not name validator", "not sealed", signed+" does not go with "+split2, "import-draft -split")
	if _, err := os.Stat(sealed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("seal wrote %s, shares its order does not take", sealed)
	}

	// The same key, split again: the order names the validator, with the
	// commitments of the first split.
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	_, first, err := software.SplitWithCommitments(sk, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	again, second, err := software.SplitWithCommitments(sk, 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	clear(sk[:])
	write := func(dir string, comm []cloud.Pubkey) string {
		t.Helper()
		return writeJSONFile(t, filepath.Join(dir, "split.json"), map[string]any{
			"t": 3, "n": 4, "shares": map[string]int{"s1": 1, "s2": 2, "s3": 3, "s4": 4},
			"validators": []any{map[string]any{"pubkey": pk, "commitments": comm}},
		})
	}
	splitA, splitB := write(fc.path("first"), first), write(fc.path("second"), second)
	signedA := orderFor(t, fc, "import-first", splitA)
	sharePub, err := core.PubkeyOf(again[1].Secret)
	if err != nil {
		t.Fatal(err)
	}
	sharesAgain := fc.path("s2-shares-again.txt")
	if err := os.WriteFile(sharesAgain, fmt.Appendf(nil, "0x%x %s 2 %s\n", again[1].Secret, pk.String(), sharePub), 0o600); err != nil {
		t.Fatal(err)
	}
	out = failTool(t, "seal", "-identity", ident, "-shares", sharesAgain, "-order", signedA, "-split", splitB, "-out", sealed)
	wantIn(t, out, "names "+pk.String()+" with the commitments_sha256", "not sealed", "import-draft -split")
	if _, err := os.Stat(sealed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("seal wrote %s, shares of another split of the key", sealed)
	}
}

// sealUnchecked writes the sealed file seal wrote before it checked that
// the order takes every share: the shares and the split given, sealed
// under the order whatever it names. It makes the file of a seal of an
// earlier build.
func sealUnchecked(t *testing.T, ident, orderPath, sharesPath, splitPath, out string) {
	t.Helper()
	f, err := readIdentityFile(ident)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.check(); err != nil {
		t.Fatal(err)
	}
	id, err := f.identity()
	if err != nil {
		t.Fatal(err)
	}
	raw := mustRead(t, orderPath)
	o, err := importorder.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	split, err := readSplit(splitPath)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := readShares(sharesPath)
	if err != nil {
		t.Fatal(err)
	}
	var (
		reqs    []cloud.SealedImportRequest
		secrets [][32]byte
	)
	for i := range shares {
		s := &shares[i]
		sp, err := core.PubkeyOf(s.secret)
		if err != nil {
			t.Fatal(err)
		}
		comm, _ := split.commitmentsOf(s.pubkey)
		reqs = append(reqs, cloud.SealedImportRequest{Pubkey: s.pubkey, SharePubkey: sp, Index: s.index,
			Order: raw, T: o.Body.T, N: o.Body.N, ShareIndex: o.Body.ShareIndex, Commitments: comm})
		secrets = append(secrets, s.secret)
	}
	batches, err := remoteadmin.SealBatchWithIdentity(id, raw, reqs, secrets)
	if err != nil {
		t.Fatal(err)
	}
	sf := &sealedFile{
		Version: 1, Signer: f.Signer, SealedAt: time.Now().UTC().Format(time.RFC3339),
		Identity: sealedIdentity{
			ImportKeySHA256: fullHex(sha256.Sum256(id.ImportKey)),
			TLSKeySHA256:    fullHex(sha256.Sum256(id.TLSKeyHash)),
			Verifier:        f.Attestation.Verifier,
			SetupSHA256:     fullHex(id.State.SetupHash),
		},
		OrderSHA256: fullHex(sha256.Sum256(raw)),
		SplitSHA256: fullHex(sha256.Sum256(mustRead(t, splitPath))),
		T:           o.Body.T, N: o.Body.N, ShareIndex: o.Body.ShareIndex,
	}
	for _, b := range batches {
		p, err := wireadmin.EncodeImportBatch(raw, b)
		if err != nil {
			t.Fatal(err)
		}
		sf.Frames = append(sf.Frames, p)
	}
	fileJSON, err := marshalFile(sf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, fileJSON, 0o644); err != nil {
		t.Fatal(err)
	}
}

// A file sealed under an order of another split (what a seal of an earlier
// build wrote once the t, n and share index matched) is refused at the
// relay with nothing sent, under the order it was sealed for and without
// one. The order of the split takes the shares: the file goes under it,
// and the relay says which order it used, so the shares need no new seal.
func TestRelayOrderOfAnotherSplit(t *testing.T) {
	fc := newFakeCluster(t)
	_, signed, _, _ := offlineTrack(t, fc)
	key2, split2, shares2 := secondSplit(t, fc, fc.path("other"))
	ident := fc.path("s2.identity.json")
	mustTool(t, "identity", "-cluster", fc.cluster, "-signer", "s2", "-out", ident)
	sealed := fc.path("s2.sealed.json")
	sealUnchecked(t, ident, signed, shares2, split2, sealed)

	r := fc.runners["s2"]
	out := failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed, "-commitments", split2, "-sealed", sealed)
	wantIn(t, out, "does not name validator "+key2, "import-draft -split", "nothing sent")
	out = failTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-sealed", sealed)
	wantIn(t, out, "does not name validator "+key2, "nothing sent")
	if r.Seen(wireadmin.TypeImportBatch) != 0 || r.Seen(wireadmin.TypeImportSealed) != 0 || len(r.Keys()) != 0 {
		t.Fatal("the relay sent shares of a file under an order that does not take them")
	}

	signed2 := orderFor(t, fc, "import-other", split2)
	out = mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s2", "-order", signed2, "-commitments", split2, "-sealed", sealed)
	wantIn(t, out, "NOTICE s2: sealed for order "+fullHex(sha256.Sum256(mustRead(t, signed)))+
		", relayed under order "+fullHex(sha256.Sum256(mustRead(t, signed2))), "s2: relayed 1 sealed shares")
	keys := r.Keys()
	if len(keys) != 1 || keys[0].Pubkey.String() != key2 {
		t.Fatalf("runner holds %v, want share 2 of %s", keys, key2)
	}
}
