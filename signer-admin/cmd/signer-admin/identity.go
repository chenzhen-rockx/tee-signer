package main

// The identity file of the offline seal: signer-admin identity exports a
// runner's verified identity (public key, attestation document, the
// verifier settings that checked it, and the issuer key set the offline
// check needs) to a public JSON file, which travels to the dealer machine
// on removable media; signer-admin seal reads it there and seals the
// shares to the runner's import key with no network. Nothing in it is
// secret: the worst a swapped file can do is fail the seal or the import.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// identityFile is the exported identity of one runner boot: everything
// signer-admin seal needs to check it again offline and seal to it. The
// JSON names of Attestation are the ones of cloud.json's attestation
// section, so a hand-checked setting reads the same here.
type identityFile struct {
	Version int    `json:"version"`
	Signer  string `json:"signer"`
	Address string `json:"address,omitempty"`
	// FetchedAt is when identity ran (RFC 3339, UTC): the file is good as
	// long as the runner does not restart.
	FetchedAt string `json:"fetched_at"`
	// ClusterID, 64 hex digits, when known: the cluster of the identity
	// command's cluster.json or setup file.
	ClusterID string `json:"cluster_id,omitempty"`
	// Chain, when known, is the runner's chain (the interchange check of
	// seal needs its genesis validators root).
	Chain       *identityChain           `json:"chain,omitempty"`
	Nonce       []byte                   `json:"nonce"` // the 32 bytes IDENTITY was asked for
	Identity    identityBody             `json:"identity"`
	Attestation runnerclient.Attestation `json:"attestation"`
	// KeySet is the issuer key set file (JWKS bytes) of the azure-maa and
	// gcp-cs verifiers, so the offline check needs no network. dev and
	// aws-nitro need none.
	KeySet []byte `json:"keyset,omitempty"`
}

// identityChain names a chain the way a setup file does.
type identityChain struct {
	GenesisForkVersion    string `json:"genesis_fork_version,omitempty"`
	GenesisValidatorsRoot string `json:"genesis_validators_root"`
}

// identityBody is backend.Identity in JSON: the setup state as its exact
// binary form (AppendSetupState), so the offline check recomputes
// backend.IdentityUserData over the same bytes.
type identityBody struct {
	State      []byte `json:"state"`
	ImportKEM  uint16 `json:"import_kem"`
	ImportKDF  uint16 `json:"import_kdf"`
	ImportAEAD uint16 `json:"import_aead"`
	ImportKey  []byte `json:"import_key"`
	TLSKeyHash []byte `json:"tls_key_hash"`
	Platform   string `json:"platform"`
	Format     string `json:"format"`
	UserData   []byte `json:"user_data"`
	Document   []byte `json:"document"`
}

// identityFileOf packs id into the file body.
func identityFileOf(id *cloud.Identity) identityBody {
	b := identityBody{
		ImportKEM: id.ImportKEM, ImportKDF: id.ImportKDF, ImportAEAD: id.ImportAEAD,
		ImportKey: id.ImportKey, TLSKeyHash: id.TLSKeyHash,
	}
	b.State = cloud.AppendSetupState(nil, &id.State)
	if id.Attestation != nil {
		b.Platform, b.Format = id.Attestation.Platform, id.Attestation.Format
		b.UserData, b.Document = id.Attestation.UserData, id.Attestation.Document
	}
	return b
}

// identity rebuilds the backend.Identity the file carries. State comes
// back through ParseSetupState, which refuses a damaged encoding, and the
// rebuilt identity hashes exactly like the runner's original one.
func (f *identityFile) identity() (*cloud.Identity, error) {
	if f.Version != 1 {
		return nil, fmt.Errorf("identity file: version %d, want 1", f.Version)
	}
	if len(f.Nonce) != 32 {
		return nil, fmt.Errorf("identity file: nonce of %d bytes, want 32", len(f.Nonce))
	}
	if f.Identity.Platform == "" || f.Identity.Document == nil {
		return nil, errors.New("identity file: no attestation document")
	}
	st, err := cloud.ParseSetupState(f.Identity.State)
	if err != nil {
		return nil, fmt.Errorf("identity file: %w", err)
	}
	return &cloud.Identity{
		State: st, ImportKEM: f.Identity.ImportKEM, ImportKDF: f.Identity.ImportKDF, ImportAEAD: f.Identity.ImportAEAD,
		ImportKey: f.Identity.ImportKey, TLSKeyHash: f.Identity.TLSKeyHash,
		Attestation: &cloud.Attestation{Platform: f.Identity.Platform, Format: f.Identity.Format,
			UserData: f.Identity.UserData, Document: f.Identity.Document},
	}, nil
}

// verifier builds the verifier of the file's settings for an offline
// check: the issuer key set is the file's own (WithKeySet), never a fetch,
// and a settings file of gcp_jwks_file, a path the dealer may not have,
// is refused. azure-maa and gcp-cs need a key set; dev and aws-nitro
// none.
func (f *identityFile) verifier() (verify.VerifyFunc, error) {
	if f.Attestation.GCPJWKSFile != "" {
		return nil, errors.New("identity file: gcp_jwks_file of the settings is a path of the online machine; export the key set into the file")
	}
	var opts []verify.Option
	switch f.Attestation.Verifier {
	case runnerclient.VerifierAzureMAA, runnerclient.VerifierGCPCS:
		if len(f.KeySet) == 0 {
			return nil, fmt.Errorf("identity file: no issuer key set, which the %s verifier needs offline", f.Attestation.Verifier)
		}
		opts = append(opts, verify.WithKeySet(f.KeySet))
	case runnerclient.VerifierDev, runnerclient.VerifierAWSNitro:
		if len(f.KeySet) > 0 {
			return nil, fmt.Errorf("identity file: an issuer key set, which the %s verifier needs none of", f.Attestation.Verifier)
		}
	default:
		return nil, fmt.Errorf("identity file: verifier %q", f.Attestation.Verifier)
	}
	return f.Attestation.NewVerifier(opts...)
}

// check runs the offline verifier on the file's identity and nonce.
func (f *identityFile) check() error {
	id, err := f.identity()
	if err != nil {
		return err
	}
	v, err := f.verifier()
	if err != nil {
		return err
	}
	return v(context.Background(), f.Nonce, id)
}

// readIdentityFile reads an identity file strictly.
func readIdentityFile(path string) (*identityFile, error) {
	var f identityFile
	if err := readStrictJSON(path, &f); err != nil {
		return nil, err
	}
	return &f, nil
}

// cmdIdentity exports a runner's verified identity for the offline seal.
// It connects the way import does (the signer's cloud.json settings, the
// setup pin of the cluster), fetches IDENTITY with a fresh nonce, has the
// connection's verifier check it, and writes the identity with the
// settings and the issuer key set to a public file. After writing it
// reads the file back and checks the identity again offline, exactly as
// seal will, so a missing key set or a bad export stops here.
func cmdIdentity(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	target := fs.String("signer", "", "the signer of cluster.json whose identity to export")
	connPath := fs.String("conn", "", "in place of -cluster and -signer: the runner's connection file (cloud.json), for a runner outside a cluster.json")
	setupPath := fs.String("setup", "", "with -conn: the runner's setup file, so the file carries the chain of the interchange check")
	outPath := fs.String("out", "identity.json", "the identity file to write (public)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	byCluster := *cf.path != "" || *target != ""
	if fs.NArg() != 0 || byCluster == (*connPath != "") || byCluster && (*cf.path == "" || *target == "" || *setupPath != "") ||
		!byCluster && *connPath == "" {
		return errors.New("usage: signer-admin identity (-cluster cluster.json -signer NAME | -conn cloud.json [-setup FILE]) -out FILE")
	}
	var (
		conn      *runnerclient.Connection
		name      string
		clusterID string
		chain     *identityChain
	)
	if byCluster {
		*cf.only = *target
		c, err := cf.load()
		if err != nil {
			return err
		}
		m := c.members[0]
		name, clusterID = m.name, fullHex(m.setup.ClusterID)
		chain = &identityChain{
			GenesisForkVersion:    "0x" + hex.EncodeToString(m.setup.Chain.GenesisForkVersion[:]),
			GenesisValidatorsRoot: "0x" + hex.EncodeToString(m.setup.Chain.GenesisValidatorsRoot[:]),
		}
		if conn, err = memberConn(m); err != nil {
			return err
		}
		// The exported settings pin the member's setup, as connectAdmin
		// does for probe and import.
		if conn.Attestation.SetupSHA256 == "" {
			conn.Attestation.SetupSHA256 = fullHex(m.setupHash)
		}
	} else {
		var err error
		if conn, err = loadConn(*connPath); err != nil {
			return err
		}
		name = conn.Address
		if *setupPath != "" {
			gvr, _, s, err := chainOf(*setupPath)
			if err != nil {
				return err
			}
			chain = &identityChain{GenesisValidatorsRoot: "0x" + hex.EncodeToString(gvr[:])}
			if s != nil {
				if err := devPlatformOnly(conn, s); err != nil {
					return fmt.Errorf("%s: %w", *setupPath, err)
				}
				clusterID = fullHex(s.ClusterID)
				chain.GenesisForkVersion = "0x" + hex.EncodeToString(s.Chain.GenesisForkVersion[:])
				chain.GenesisValidatorsRoot = "0x" + hex.EncodeToString(s.Chain.GenesisValidatorsRoot[:])
			}
		}
	}
	cl, err := conn.New(runnerclient.WithTimeout(*cf.timeout))
	if err != nil {
		return err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *cf.timeout)
	defer cancel()
	id, nonce, err := remoteadmin.Wrap(cl.Client).VerifiedIdentity(ctx, cl.Verify)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	// The issuer key set the offline check needs, fetched now: the dealer
	// machine has no network.
	var keyset []byte
	switch conn.Attestation.Verifier {
	case runnerclient.VerifierAzureMAA:
		keyset, err = attest.DiscoverJWKSBytes(ctx, &http.Client{Timeout: 15 * time.Second}, "https://"+conn.Attestation.MAAHost)
	case runnerclient.VerifierGCPCS:
		issuer := conn.Attestation.GCPIssuer
		if issuer == "" {
			issuer = attest.ConfidentialSpaceIssuer
		}
		keyset, err = attest.DiscoverJWKSBytes(ctx, &http.Client{Timeout: 15 * time.Second}, issuer)
	}
	if err != nil {
		return fmt.Errorf("%s: issuer key set: %w", name, err)
	}
	f := &identityFile{
		Version: 1, Signer: name, Address: conn.Address,
		FetchedAt:   time.Now().UTC().Format(time.RFC3339),
		ClusterID:   clusterID,
		Chain:       chain,
		Nonce:       nonce,
		Identity:    identityFileOf(id),
		Attestation: conn.Attestation,
		KeySet:      keyset,
	}
	b, err := marshalFile(f)
	if err != nil {
		return err
	}
	if err := writeAtomic(*outPath, b, 0o644); err != nil {
		return err
	}
	// Read it back and check the identity offline, as seal will: a missing
	// key set or a damaged export stops here, not on the dealer.
	g, err := readIdentityFile(*outPath)
	if err != nil {
		return err
	}
	if err := g.check(); err != nil {
		return fmt.Errorf("%s: read back: %w", *outPath, err)
	}
	fprintf(out, "identity of %s (verifier %s): setup %s, import key %s, tls key %s",
		name, f.Attestation.Verifier, hex8(id.State.SetupHash), hex8(sha256.Sum256(id.ImportKey)), hex8(sha256.Sum256(id.TLSKeyHash)))
	if chain != nil {
		fprintf(out, ", chain %s", chain.GenesisForkVersion)
	}
	fprintf(out, "; valid until the runner restarts; wrote %s\n", *outPath)
	return nil
}
