//go:build linux

package csp

import (
	"errors"
	"testing"
)

func TestChainStatus_OK(t *testing.T) {
	if !ChainStatus(0).OK() {
		t.Error("zero status must be OK")
	}
	if ChainStatus(TrustIsRevoked).OK() {
		t.Error("non-zero status must not be OK")
	}
}

func TestChainStatus_String(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status ChainStatus
		want   string
	}{
		{"trusted", 0, "ok"},
		{"revoked", ChainStatus(TrustIsRevoked), "IS_REVOKED"},
		{"expired", ChainStatus(TrustIsNotTimeValid), "IS_NOT_TIME_VALID"},
		{"untrusted root", ChainStatus(TrustIsUntrustedRoot), "IS_UNTRUSTED_ROOT"},
		{
			"expired and untrusted",
			ChainStatus(TrustIsNotTimeValid | TrustIsUntrustedRoot),
			"IS_NOT_TIME_VALID|IS_UNTRUSTED_ROOT",
		},
		{"undocumented bit", ChainStatus(0x00000800), "unknown error status 0x00000800"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.status.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestChainStatus_Problems(t *testing.T) {
	if got := ChainStatus(0).Problems(); got != nil {
		t.Errorf("Problems() on trusted chain = %v, want nil", got)
	}

	status := ChainStatus(TrustIsRevoked | TrustRevocationStatusUnknown)
	got := status.Problems()
	if len(got) != 2 {
		t.Fatalf("Problems() = %v, want 2 entries", got)
	}
	// IS_REVOKED is listed first: the ordering is deliberate, most specific first.
	if got[0] != "IS_REVOKED" {
		t.Errorf("Problems()[0] = %q, want IS_REVOKED", got[0])
	}
}

func TestChainStatus_Has(t *testing.T) {
	status := ChainStatus(TrustIsNotTimeValid | TrustIsPartialChain)

	if !status.Has(TrustIsNotTimeValid) {
		t.Error("Has(TrustIsNotTimeValid) = false, want true")
	}
	if status.Has(TrustIsRevoked) {
		t.Error("Has(TrustIsRevoked) = true, want false")
	}
}

func TestBuildChain_ZeroCertificate(t *testing.T) {
	_, err := BuildChain(Cert{}, nil, RevocationCheckChainExcludeRoot)
	if !errors.Is(err, ErrZeroCertificate) {
		t.Errorf("BuildChain(zero cert) error = %v, want ErrZeroCertificate", err)
	}
}

// chainFromFixture parses a detached signature fixture and returns the signer
// certificate together with the message certificate store. Both must be closed
// by the caller.
func chainFromFixture(t *testing.T, dataName, sigName string) (Cert, CertStore, *Msg) {
	t.Helper()

	data := loadFixture(t, dataName)
	sig := loadFixture(t, sigName)

	msg, err := OpenToVerify(sig)
	if err != nil {
		t.Fatalf("OpenToVerify: %v", err)
	}
	if _, err = msg.Write(data); err != nil {
		t.Fatalf("write data: %v", err)
	}

	store, err := msg.CertStore()
	if err != nil {
		t.Fatalf("CertStore: %v", err)
	}

	cert, err := msg.GetSignerCert(0, store)
	if err != nil {
		t.Fatalf("GetSignerCert: %v", err)
	}
	if cert.IsZero() {
		t.Fatal("signer certificate not found in message")
	}

	return cert, store, msg
}

func TestBuildChain_GoodSignature(t *testing.T) {
	cert, store, msg := chainFromFixture(t, "testdata/good.xml", "testdata/good.xml.sig")
	defer func() { _ = msg.Close() }()
	defer func() { _ = store.Close() }()
	defer func() { _ = cert.Close() }()

	status, err := BuildChain(cert, &store, RevocationCheckChainExcludeRoot)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	if !status.OK() {
		t.Errorf("BuildChain status = %v, want ok", status)
	}
}

func TestBuildChain_ExpiredSignature(t *testing.T) {
	cert, store, msg := chainFromFixture(t, "testdata/expired.xml", "testdata/expired.xml.sig")
	defer func() { _ = msg.Close() }()
	defer func() { _ = store.Close() }()
	defer func() { _ = cert.Close() }()

	status, err := BuildChain(cert, &store, RevocationCheckChainExcludeRoot)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}
	if status.OK() {
		t.Fatal("BuildChain accepted an expired certificate")
	}
	if !status.Has(TrustIsNotTimeValid) {
		t.Errorf("BuildChain status = %v, want IS_NOT_TIME_VALID to be set", status)
	}
}

// TestBuildChain_CacheOnlyDoesNotReachNetwork documents the semantics of
// RevocationCheckCacheOnly: with a cold cache it reports the revocation status
// as unknown instead of failing, which is what makes it usable as a fast path.
func TestBuildChain_CacheOnlyDoesNotReachNetwork(t *testing.T) {
	cert, store, msg := chainFromFixture(t, "testdata/good.xml", "testdata/good.xml.sig")
	defer func() { _ = msg.Close() }()
	defer func() { _ = store.Close() }()
	defer func() { _ = cert.Close() }()

	status, err := BuildChain(cert, &store,
		RevocationCheckChainExcludeRoot|RevocationCheckCacheOnly)
	if err != nil {
		t.Fatalf("BuildChain: %v", err)
	}

	// Either the CRL is already cached (status ok) or it is not (status
	// unknown) — both are valid outcomes, an error is not.
	if !status.OK() && !status.Has(TrustRevocationStatusUnknown) {
		t.Errorf("BuildChain cache-only = %v, want ok or REVOCATION_STATUS_UNKNOWN", status)
	}
}
