package main

// The offline seal: signer-admin seal reads an identity file of signer-admin
// identity and a plaintext shares file on the dealer machine, checks the
// identity offline (the file's verifier settings and issuer key set; no
// network), and seals each share to the runner's attested import key with
// the same HPKE the online import uses. The sealed file it writes holds
// IMPORT_SHARES_SEALED frames as the runner takes them, so the online
// machine that relays it (signer-admin import -sealed) never sees a
// plaintext share: the media between the two machines carry ciphertext.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/importorder"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// sealedFile is the output of seal and the input of import -sealed: the
// sealed shares as IMPORT_SHARES_SEALED frames (base64), with the
// fingerprints the relay checks before it sends anything. Every byte of it
// is ciphertext or public: the sealed shares open under the import key of
// one runner boot only.
type sealedFile struct {
	Version  int            `json:"version"`
	Signer   string         `json:"signer"`
	SealedAt string         `json:"sealed_at"`
	Identity sealedIdentity `json:"identity"`
	// SplitSHA256, 64 hex digits, is of the split file the shares were
	// sealed under, and T, N and ShareIndex are that split; all omitted
	// when there was none (a runner without a setup). OrderSHA256 is of the
	// signed order they were sealed under, omitted when there was none:
	// with a split and no order the file waits for the order the approvers
	// sign for that split, which import -sealed attaches (checkSealed).
	OrderSHA256 string `json:"order_sha256,omitempty"`
	SplitSHA256 string `json:"split_sha256,omitempty"`
	T           uint8  `json:"t,omitempty"`
	N           uint8  `json:"n,omitempty"`
	ShareIndex  uint8  `json:"share_index,omitempty"`
	// Frames are EncodeImportBatch bodies with at most wireadmin.MaxBatch
	// shares, one frame's worth of bytes each, under the order when there
	// was one. A share's split goes in its frame under an order; without
	// one the relay adds it from the order and the split file.
	Frames [][]byte `json:"frames"`
}

// sealedIdentity names the runner boot the shares are sealed to.
type sealedIdentity struct {
	// ImportKeySHA256, of the runner's HPKE import key, is what the relay
	// compares the live runner's key against: a runner that restarted
	// since the seal has another key and cannot open the file.
	ImportKeySHA256 string `json:"import_key_sha256"`
	TLSKeySHA256    string `json:"tls_key_sha256,omitempty"`
	SetupSHA256     string `json:"setup_sha256,omitempty"`
	Verifier        string `json:"verifier"`
}

// marshalFile writes v as indented JSON with a trailing newline.
func marshalFile(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// readSealedFile reads a sealed file strictly.
func readSealedFile(path string) (*sealedFile, error) {
	var f sealedFile
	if err := readStrictJSON(path, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// cmdSeal seals a shares file to the identity of one runner boot, offline.
// It makes no network call: the identity file's attestation document is
// checked with the settings and key set it carries, the shares are checked
// against the split and the order exactly as import checks them before it
// dials, and each share is sealed with the runner's public import key.
//
// The order is optional. Sealed with -order, the file holds frames the
// relay sends as they are. Sealed with -split alone, the shares are checked
// against the split (the signer's share index is the split's) and the file
// waits for the order the approvers sign for that split: the dealer is
// visited once, split and seal together, and import -sealed attaches the
// order (checkSealed). The sealed bytes bind the share's header, not the
// order, and the runner checks the order it is sent.
func cmdSeal(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	identPath := fs.String("identity", "", "the identity file of signer-admin identity (required)")
	sharesPath := fs.String("shares", "", "the shares file: one share per line, mode 0600")
	orderPath := fs.String("order", "", "the signed import order (import.signed); without it the shares are sealed for the signer's share index of -split and import -sealed attaches the order")
	splitPath := fs.String("split", "", "the split file of import-draft, for each validator's commitments")
	icPath := fs.String("interchange", "", "EIP-3076 slashing protection file (format 5), sealed in with each share")
	outPath := fs.String("out", "sealed.json", "the sealed file to write (ciphertext)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *identPath == "" || *sharesPath == "" || (*orderPath != "" && *splitPath == "") {
		return errors.New("usage: signer-admin seal -identity FILE -shares FILE [-order import.signed] [-split split.json] " +
			"[-interchange FILE] -out FILE")
	}
	// The shares file is plaintext: no core dumps from here on.
	if err := lockSecrets(os.Stderr); err != nil {
		return err
	}
	// The identity first, before any secret is read: a file that does not
	// check out stops the seal with the shares untouched.
	f, err := readIdentityFile(*identPath)
	if err != nil {
		return err
	}
	if err := f.check(); err != nil {
		return fmt.Errorf("%s: %w", *identPath, err)
	}
	id, err := f.identity()
	if err != nil {
		return fmt.Errorf("%s: %w", *identPath, err)
	}
	var (
		raw   []byte
		o     *importorder.Order
		split *splitFile
		// index is the share index the shares must have: the order's under
		// an order, else the signer's in the split.
		index uint8
	)
	if *splitPath != "" {
		if split, err = readSplit(*splitPath); err != nil {
			return err
		}
	}
	if *orderPath != "" {
		if raw, err = os.ReadFile(*orderPath); err != nil {
			return err
		}
		if o, err = importorder.Decode(raw); err != nil {
			return fmt.Errorf("%s: %w", *orderPath, err)
		}
		index = o.Body.ShareIndex
		if split.T != o.Body.T || split.N != o.Body.N {
			return fmt.Errorf("%s is a %d of %d split, the order names %d of %d", *splitPath, split.T, split.N, o.Body.T, o.Body.N)
		}
		// The order must name this runner's setup: an identity file of
		// another signer of the cluster stops here, before any secret is
		// read.
		if [32]byte(id.State.SetupHash) != o.Body.Target {
			return fmt.Errorf("%s is an import order for setup %s, the identity of %s is of setup %s",
				*orderPath, hex8(o.Body.Target), f.Signer, hex8(id.State.SetupHash))
		}
		if f.ClusterID != "" {
			var clID [32]byte
			if b, err := hex.DecodeString(f.ClusterID); err != nil || len(b) != 32 {
				return fmt.Errorf("%s: cluster_id is not 64 hex digits", *identPath)
			} else {
				copy(clID[:], b)
			}
			if clID != o.Body.ClusterID {
				return fmt.Errorf("%s is an import order for cluster %s, the identity of %s is of cluster %s",
					*orderPath, hex8(o.Body.ClusterID), f.Signer, hex8(clID))
			}
		}
	} else if split != nil {
		// No order, a split: the signer's share index is the split's, so
		// the order the approvers sign for this split fits these shares.
		var ok bool
		if index, ok = split.Shares[f.Signer]; !ok || index == 0 || index > split.N {
			return fmt.Errorf("%s is a %d of %d split with no share for %s, the identity is %s's; without -order the seal takes the share index from it",
				*splitPath, split.T, split.N, f.Signer, f.Signer)
		}
	}
	shares, err := readShares(*sharesPath)
	if err != nil {
		return err
	}
	defer func() {
		for i := range shares {
			clear(shares[i].secret[:])
		}
	}()
	if split != nil {
		if err := checkShareIndex(*sharesPath, shares, split, index); err != nil {
			return err
		}
	}
	var ic *interchange
	if *icPath != "" {
		if f.Chain == nil {
			return errors.New("-interchange needs the identity file to carry the chain: export it with -setup, or from cluster.json")
		}
		if ic, err = loadInterchange(*icPath); err != nil {
			return err
		}
		var gvr cloud.Root
		if b, err := hex.DecodeString(trim0x(f.Chain.GenesisValidatorsRoot)); err != nil || len(b) != 32 {
			return fmt.Errorf("%s: chain genesis_validators_root is not 64 hex digits", *identPath)
		} else {
			copy(gvr[:], b)
		}
		// History of another chain says nothing about this one, and its
		// maxima would set the runner's floor for this chain.
		if ic.gvr != gvr {
			return fmt.Errorf("%s: genesis_validators_root %s is not the runner's chain %s (refusing)", *icPath, ic.gvr, gvr)
		}
	}
	// The shares to seal, each with its secret, as the online import
	// builds them for SealBatches.
	var (
		reqs       []cloud.SealedImportRequest
		secrets    [][32]byte
		failed     bool
		otherSplit bool // a share the order does not take: an order of another split
	)
	defer clear(secrets)
	for i := range shares {
		s := &shares[i] // not a copy of the secret
		sp, err := core.PubkeyOf(s.secret)
		if err != nil || s.sharePub != (cloud.Pubkey{}) && sp != s.sharePub {
			failed = true
			fprintf(out, "%s %s: the share is not a valid BLS secret key of its share pubkey\n", f.Signer, s.pubkey)
			continue
		}
		r := cloud.SealedImportRequest{Pubkey: s.pubkey, SharePubkey: sp, Index: s.index}
		if split != nil {
			comm, ok := split.commitmentsOf(s.pubkey)
			if !ok {
				failed = true
				fprintf(out, "%s %s: not in the split file, not sealed\n", f.Signer, s.pubkey)
				continue
			}
			if o != nil {
				// The order must take the share, as the runner checks
				// (checkOrderShare), and its split goes with the share in
				// the frame. Without an order there is nothing to check yet
				// and the frame carries no split (the wire format needs the
				// order for it): import -sealed checks the order it
				// attaches and adds the split from it and the split file.
				r.T, r.N, r.ShareIndex, r.Commitments = o.Body.T, o.Body.N, o.Body.ShareIndex, comm
				if err := checkOrderShare(&o.Body, &r); err != nil {
					failed, otherSplit = true, true
					fprintf(out, "%s %s: %v, not sealed\n", f.Signer, s.pubkey, err)
					continue
				}
			}
		}
		if ic != nil {
			if r.Interchange, err = ic.markOf(s.pubkey); err != nil {
				failed = true
				fprintf(out, "%s %s: %v, not sealed\n", f.Signer, s.pubkey, err)
				continue
			}
			if w := r.Interchange; w == nil {
				fprintf(out, "%s %s: interchange: no signed history for this validator\n", f.Signer, s.pubkey)
			} else {
				fprintf(out, "%s %s: interchange maxima block_slot %d (%t) source %d target %d (%t)\n", f.Signer, s.pubkey,
					w.BlockSlot, w.HasBlock, w.SourceEpoch, w.TargetEpoch, w.HasAttestation)
			}
		}
		reqs, secrets = append(reqs, r), append(secrets, s.secret)
	}
	if failed {
		if otherSplit {
			fprintf(out, "%s does not go with %s: %s\n", *orderPath, *splitPath, orderOtherSplit)
		}
		return errReported
	}
	if len(reqs) == 0 {
		return errors.New("no shares to seal")
	}
	batches, err := remoteadmin.SealBatchWithIdentity(id, raw, reqs, secrets)
	if err != nil {
		return err
	}
	sf := &sealedFile{
		Version: 1, Signer: f.Signer, SealedAt: time.Now().UTC().Format(time.RFC3339),
		Identity: sealedIdentity{
			ImportKeySHA256: fullHex(sha256.Sum256(id.ImportKey)),
			TLSKeySHA256:    fullHex(sha256.Sum256(id.TLSKeyHash)),
			Verifier:        f.Attestation.Verifier,
		},
	}
	if len(id.TLSKeyHash) == 0 {
		sf.Identity.TLSKeySHA256 = ""
	}
	sf.Identity.SetupSHA256 = fullHex(id.State.SetupHash)
	if split != nil {
		if splitRaw, err := os.ReadFile(*splitPath); err != nil {
			return err
		} else {
			sf.SplitSHA256 = fullHex(sha256.Sum256(splitRaw))
		}
		sf.T, sf.N, sf.ShareIndex = split.T, split.N, index
	}
	if o != nil {
		sf.OrderSHA256 = fullHex(sha256.Sum256(raw))
	}
	for _, b := range batches {
		p, err := wireadmin.EncodeImportBatch(raw, b)
		if err != nil {
			return err
		}
		sf.Frames = append(sf.Frames, p)
	}
	fileJSON, err := marshalFile(sf)
	if err != nil {
		return err
	}
	if err := writeAtomic(*outPath, fileJSON, 0o644); err != nil {
		return err
	}
	// Read it back: the frames decode, and what decodes is what was
	// sealed, header by header and byte for byte.
	g, err := readSealedFile(*outPath)
	if err != nil {
		return err
	}
	if err := checkSealedFrames(g, batches, raw); err != nil {
		return fmt.Errorf("%s: read back: %w", *outPath, err)
	}
	fprintf(out, "sealed %d shares of %s (verifier %s) to import key %s", len(reqs), f.Signer, f.Attestation.Verifier, hex8(sha256.Sum256(id.ImportKey)))
	if o != nil {
		fprintf(out, ", %d of %d, share index %d, order %s", o.Body.T, o.Body.N, o.Body.ShareIndex, hex8(sha256.Sum256(raw)))
	} else if split != nil {
		fprintf(out, ", %d of %d, share index %d, no import order yet: on the online machine draft and sign the orders from the split file, and relay with -order and -commitments",
			split.T, split.N, index)
	}
	fprintf(out, "; wrote %s — the file is ciphertext, valid until the runner restarts; carry only it to the online machine\n", *outPath)
	return nil
}

// checkSealedFrames compares a read-back sealed file with the batches it
// was written from.
func checkSealedFrames(g *sealedFile, batches [][]cloud.SealedImportRequest, order []byte) error {
	if g.Version != 1 {
		return fmt.Errorf("version %d, want 1", g.Version)
	}
	if len(g.Frames) != len(batches) {
		return fmt.Errorf("%d frames, want %d", len(g.Frames), len(batches))
	}
	for i, b := range batches {
		reqs, err := wireadmin.DecodeImportBatch(g.Frames[i])
		if err != nil {
			return fmt.Errorf("frame %d: %w", i+1, err)
		}
		if len(reqs) != len(b) {
			return fmt.Errorf("frame %d: %d shares, want %d", i+1, len(reqs), len(b))
		}
		for j := range reqs {
			if reqs[j].Pubkey != b[j].Pubkey || reqs[j].SharePubkey != b[j].SharePubkey || reqs[j].Index != b[j].Index ||
				reqs[j].T != b[j].T || reqs[j].N != b[j].N || reqs[j].ShareIndex != b[j].ShareIndex {
				return fmt.Errorf("frame %d share %d: header changed", i+1, j+1)
			}
			if string(reqs[j].Sealed) != string(b[j].Sealed) {
				return fmt.Errorf("frame %d share %d: sealed bytes changed", i+1, j+1)
			}
			if order != nil && (len(reqs[j].Order) == 0 || string(reqs[j].Order) != string(order)) {
				return fmt.Errorf("frame %d share %d: order changed", i+1, j+1)
			}
		}
	}
	return nil
}

// trim0x strips one 0x of a hex string.
func trim0x(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return s
}

// checkSealed checks a sealed file before anything is sent: the signer it
// names, the fingerprints of the order and the split when the relay names
// them, the frames, which must decode and match the split, and that the
// order takes every share. It returns the decoded frames, one slice per
// frame, ready to send, and a notice when the relay's order is not the one
// the file was sealed under.
//
// The sealed bytes bind the share's header only (package sealedimport),
// not the order or the split fields: the runner checks those against the
// order it is sent. So a file sealed with a split and no order waits for
// the order the approvers sign for that split, and the relay attaches it
// with the split; and a file sealed under one order goes under another
// that takes its shares the same way. What the runner would refuse for is
// refused here, with nothing sent.
func checkSealed(sf *sealedFile, name string, raw []byte, o *importorder.Order, split *splitFile, commPath string) ([][]cloud.SealedImportRequest, string, error) {
	if sf.Version != 1 {
		return nil, "", fmt.Errorf("version %d, want 1", sf.Version)
	}
	if sf.Signer != name {
		return nil, "", fmt.Errorf("sealed for signer %q, this is %q", sf.Signer, name)
	}
	if b, err := hex.DecodeString(sf.Identity.ImportKeySHA256); err != nil || len(b) != 32 {
		return nil, "", errors.New("identity.import_key_sha256 is not 64 hex digits")
	}
	if len(sf.Frames) == 0 {
		return nil, "", errors.New("no frames")
	}
	// waiting: sealed with a split and no order, for the order the relay
	// attaches.
	waiting := sf.SplitSHA256 != "" && sf.OrderSHA256 == ""
	if waiting && (o == nil || split == nil || commPath == "") {
		return nil, "", errors.New("sealed without an import order: relay it with -order, the order the approvers signed for its split, and -commitments, that split file")
	}
	var notice string
	if o != nil {
		if sf.OrderSHA256 == "" && !waiting {
			return nil, "", errors.New("sealed without an order, but the relay names one")
		}
		if sf.OrderSHA256 != "" && sf.OrderSHA256 != fullHex(sha256.Sum256(raw)) {
			notice = fmt.Sprintf("sealed for order %s, relayed under order %s", sf.OrderSHA256, fullHex(sha256.Sum256(raw)))
		}
		if sf.T != o.Body.T || sf.N != o.Body.N || sf.ShareIndex != o.Body.ShareIndex {
			return nil, "", fmt.Errorf("sealed for a %d of %d split of share index %d, the order names %d of %d, share index %d",
				sf.T, sf.N, sf.ShareIndex, o.Body.T, o.Body.N, o.Body.ShareIndex)
		}
		if sf.Identity.SetupSHA256 != "" && sf.Identity.SetupSHA256 != fullHex(o.Body.Target) {
			return nil, "", fmt.Errorf("sealed for setup %s, the order names setup %s", sf.Identity.SetupSHA256, fullHex(o.Body.Target))
		}
	}
	var frames [][]cloud.SealedImportRequest
	for i, p := range sf.Frames {
		reqs, err := wireadmin.DecodeImportBatch(p)
		if err != nil {
			return nil, "", fmt.Errorf("frame %d: %w", i+1, err)
		}
		if len(reqs) == 0 {
			return nil, "", fmt.Errorf("frame %d holds no share", i+1)
		}
		frames = append(frames, reqs)
	}
	if split != nil && commPath != "" && sf.SplitSHA256 != "" {
		b, err := os.ReadFile(commPath)
		if err != nil {
			return nil, "", err
		}
		if sf.SplitSHA256 != fullHex(sha256.Sum256(b)) {
			return nil, "", fmt.Errorf("sealed for split %s, %s is %s", sf.SplitSHA256, commPath, fullHex(sha256.Sum256(b)))
		}
		for fi, reqs := range frames {
			for ri, r := range reqs {
				if r.T == 0 {
					continue
				}
				comm, ok := split.commitmentsOf(r.Pubkey)
				if !ok {
					return nil, "", fmt.Errorf("frame %d share %d: %s is not in the split file", fi+1, ri+1, r.Pubkey)
				}
				if !slices.Equal(r.Commitments, comm) {
					return nil, "", fmt.Errorf("frame %d share %d: commitments of %s differ from the split file", fi+1, ri+1, r.Pubkey)
				}
				if r.N != split.N {
					return nil, "", fmt.Errorf("frame %d share %d: n %d, the split file says %d", fi+1, ri+1, r.N, split.N)
				}
			}
		}
	}
	// The order takes every share, as the runner checks before it opens
	// one: the share is of the order's split (t, n, share index), the order
	// names its validator with the hash of its commitments
	// (checkOrderShare), and the share is the commitments' point at the
	// share index. The order is the relay's; a file sealed under one and
	// relayed without -order carries it in its frames.
	for fi, reqs := range frames {
		var body *importorder.Body
		if o != nil {
			body = &o.Body
		} else if len(reqs[0].Order) > 0 {
			embedded, err := importorder.Decode(reqs[0].Order)
			if err != nil {
				return nil, "", fmt.Errorf("frame %d: the import order it carries: %v", fi+1, err)
			}
			body = &embedded.Body
		}
		if body == nil {
			continue
		}
		for ri := range reqs {
			r := &reqs[ri]
			if r.T == 0 && !waiting {
				continue
			}
			full := *r
			if waiting {
				// The split comes from the split file the relay names, which
				// is the one the shares were sealed for (SplitSHA256); the
				// order from the relay.
				comm, ok := split.commitmentsOf(r.Pubkey)
				if !ok {
					return nil, "", fmt.Errorf("frame %d share %d: %s is not in the split file", fi+1, ri+1, r.Pubkey)
				}
				full.Order, full.T, full.N, full.ShareIndex, full.Commitments = raw, o.Body.T, o.Body.N, o.Body.ShareIndex, comm
			} else if o != nil {
				full.Order = raw // the relay's order, when it is not the one sealed under
			}
			if full.T != body.T || full.N != body.N || full.ShareIndex != body.ShareIndex {
				return nil, "", fmt.Errorf("frame %d share %d: a share of a %d of %d split of share index %d, the order names %d of %d, share index %d; nothing sent",
					fi+1, ri+1, full.T, full.N, full.ShareIndex, body.T, body.N, body.ShareIndex)
			}
			if err := checkOrderShare(body, &full); err != nil {
				return nil, "", fmt.Errorf("frame %d share %d: %v; nothing sent. %s", fi+1, ri+1, err, orderOtherSplit)
			}
			if want, err := threshold.FeldmanEval(full.Commitments, uint64(full.ShareIndex)); err != nil || want != full.SharePubkey {
				return nil, "", fmt.Errorf("frame %d share %d: share_pubkey %s is not share %d of validator %s; nothing sent",
					fi+1, ri+1, full.SharePubkey, full.ShareIndex, full.Pubkey)
			}
			reqs[ri] = full
		}
	}
	return frames, notice, nil
}

// relaySealed sends the frames of an offline seal to the runner as they
// came out of checkSealed, each share under the order the relay names:
// nothing on this machine reads a share. The live runner's import key
// is checked against the one the file was sealed to first — a runner that
// restarted since the seal cannot open the file, and sealing again on the
// dealer is cheap. held names the validators the runner holds already
// (-skip-loaded); a share of one is left out, by its public header alone.
func relaySealed(out io.Writer, name string, cl *runnerclient.Client, timeout time.Duration, sf *sealedFile,
	frames [][]cloud.SealedImportRequest, held map[cloud.Pubkey]bool) error {
	ac := remoteadmin.Wrap(cl.Client)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	id, _, err := ac.VerifiedIdentity(ctx, cl.Verify)
	cancel()
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if fullHex(sha256.Sum256(id.ImportKey)) != sf.Identity.ImportKeySHA256 {
		return fmt.Errorf("%s restarted since the file was sealed (its import key changed); re-run signer-admin identity here and signer-admin seal on the dealer — the shares never left the dealer machine", name)
	}
	start, skipped := time.Now(), 0
	var send [][]cloud.SealedImportRequest
	for _, reqs := range frames {
		var keep []cloud.SealedImportRequest
		for _, r := range reqs {
			if held[r.Pubkey] {
				skipped++
				continue
			}
			keep = append(keep, r)
		}
		if len(keep) > 0 {
			send = append(send, keep)
		}
	}
	total := 0
	for _, b := range send {
		total += len(b)
	}
	if total == 0 {
		fprintf(out, "%s: every share of the file is held already\n", name)
		return nil
	}
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	batched, err := ac.BatchImport(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("%s: batch import probe: %w", name, err)
	}
	list := total <= 16
	var imported int
	if batched {
		order := send[0][0].Order
		n, err := sendBatches(ac, order, send, total, timeout, out, name, list)
		imported += n
		if err != nil {
			return relayErr(name, err)
		}
	} else {
		for _, b := range send {
			for j := range b {
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				k, err := ac.ImportSealed(ctx, &b[j])
				cancel()
				if err != nil {
					return relayErr(name, err)
				}
				imported++
				if list {
					fprintf(out, "%s imported %s share_pubkey %s index %d (sealed offline, relayed)\n", name, k.Pubkey, k.SharePubkey, k.Index)
				}
			}
		}
	}
	fprintf(out, "%s: relayed %d sealed shares, skipped %d held already, in %s\n", name, imported, skipped, time.Since(start).Round(time.Millisecond))
	return nil
}

// relayErr adds the re-seal hint to a refusal that means the sealed file
// does not open under the runner's import key: another boot, or a header
// changed in transit.
func relayErr(name string, err error) error {
	if cloud.StatusOf(err) == cloud.StatusBadKey {
		return fmt.Errorf("%s: %w; the file does not open under this boot's import key — re-run signer-admin identity here and signer-admin seal on the dealer", name, err)
	}
	return fmt.Errorf("%s: %w", name, err)
}
