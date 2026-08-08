//go:build linux

package csp

/*
#include "common.h"

// Fallbacks for symbols that may or may not be declared by CryptoPro headers
// on every CSP release. Values come from MS wincrypt.h.
#ifndef CERT_CHAIN_REVOCATION_CHECK_END_CERT
#define CERT_CHAIN_REVOCATION_CHECK_END_CERT 0x10000000
#endif
#ifndef CERT_CHAIN_REVOCATION_CHECK_CHAIN
#define CERT_CHAIN_REVOCATION_CHECK_CHAIN 0x20000000
#endif
#ifndef CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
#define CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT 0x40000000
#endif
#ifndef CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY
#define CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY 0x80000000
#endif

// build_chain builds and evaluates a certificate chain for pCert using the
// default (process-wide, caching) chain engine.
//
// Passing NULL as the engine is deliberate: the default engine keeps an
// in-memory cache of built chains and fetched CRLs, which is what makes
// repeated verifications cheap. Creating a private engine per call would
// defeat that.
//
// hAdditionalStore supplies intermediate certificates that are not in a
// system store. For a detached CMS signature this is the message's own
// certificate store — without it the issuer of the signer certificate
// usually cannot be located and the chain comes back as a partial one.
//
// On success out_error_status receives CERT_TRUST_STATUS.dwErrorStatus,
// where 0 means "chain built to a trusted root with no complaints".
static BOOL build_chain(
        PCCERT_CONTEXT pCert,
        HCERTSTORE hAdditionalStore,
        DWORD flags,
        DWORD* out_error_status,
        DWORD* out_last_error) {
    CERT_CHAIN_PARA chainPara;
    PCCERT_CHAIN_CONTEXT chainContext = NULL;

    memset(&chainPara, 0, sizeof(chainPara));
    chainPara.cbSize = sizeof(chainPara);

    if (!CertGetCertificateChain(
            NULL,
            pCert,
            NULL,
            hAdditionalStore,
            &chainPara,
            flags,
            NULL,
            &chainContext)) {
        // Capture GetLastError in the same cgo crossing as the failing call:
        // Go may reschedule the goroutine onto a different OS thread before
        // getErr() runs, which would read another worker's thread-local value.
        *out_last_error = GetLastError();
        return FALSE;
    }

    *out_error_status = chainContext->TrustStatus.dwErrorStatus;
    CertFreeCertificateChain(chainContext);
    return TRUE;
}
*/
import "C"

import (
	"errors"
	"strings"
)

// Revocation checking modes for BuildChain. They mirror the
// CERT_CHAIN_REVOCATION_CHECK_* flags from <wincrypt.h>.
const (
	// RevocationCheckNone skips revocation entirely: the chain is only built
	// and its signatures, validity dates and trust anchor are evaluated.
	RevocationCheckNone uint32 = 0
	// RevocationCheckEndCert checks revocation of the end certificate only.
	RevocationCheckEndCert uint32 = 0x10000000
	// RevocationCheckChain checks revocation for every certificate in the chain.
	RevocationCheckChain uint32 = 0x20000000
	// RevocationCheckChainExcludeRoot checks revocation for the whole chain
	// except the self-signed root. This is the closest equivalent of what
	// `cryptcp -verify -errchain` does and is the recommended default.
	RevocationCheckChainExcludeRoot uint32 = 0x40000000
	// RevocationCheckCacheOnly forbids network retrieval: revocation is
	// resolved from the local cache and stores only. Combine with one of the
	// modes above. Without a populated cache this yields
	// TrustRevocationStatusUnknown rather than an error.
	RevocationCheckCacheOnly uint32 = 0x80000000
)

// CERT_TRUST_* error bits reported through ChainStatus.
const (
	TrustIsNotTimeValid          uint32 = 0x00000001
	TrustIsRevoked               uint32 = 0x00000004
	TrustIsNotSignatureValid     uint32 = 0x00000008
	TrustIsNotValidForUsage      uint32 = 0x00000010
	TrustIsUntrustedRoot         uint32 = 0x00000020
	TrustRevocationStatusUnknown uint32 = 0x00000040
	TrustIsCyclic                uint32 = 0x00000080
	TrustIsPartialChain          uint32 = 0x00010000
	TrustCtlIsNotTimeValid       uint32 = 0x00020000
	TrustCtlIsNotSignatureValid  uint32 = 0x00040000
	TrustCtlIsNotValidForUsage   uint32 = 0x00080000
	TrustIsOfflineRevocation     uint32 = 0x01000000
	TrustNoIssuanceChainPolicy   uint32 = 0x02000000
)

// chainStatusNames maps CERT_TRUST_* bits to their symbolic names, ordered
// from most to least specific so that String() reads sensibly.
var chainStatusNames = []struct {
	bit  uint32
	name string
}{
	{TrustIsRevoked, "IS_REVOKED"},
	{TrustIsNotTimeValid, "IS_NOT_TIME_VALID"},
	{TrustIsNotSignatureValid, "IS_NOT_SIGNATURE_VALID"},
	{TrustIsNotValidForUsage, "IS_NOT_VALID_FOR_USAGE"},
	{TrustIsUntrustedRoot, "IS_UNTRUSTED_ROOT"},
	{TrustIsPartialChain, "IS_PARTIAL_CHAIN"},
	{TrustIsCyclic, "IS_CYCLIC"},
	{TrustRevocationStatusUnknown, "REVOCATION_STATUS_UNKNOWN"},
	{TrustIsOfflineRevocation, "IS_OFFLINE_REVOCATION"},
	{TrustCtlIsNotTimeValid, "CTL_IS_NOT_TIME_VALID"},
	{TrustCtlIsNotSignatureValid, "CTL_IS_NOT_SIGNATURE_VALID"},
	{TrustCtlIsNotValidForUsage, "CTL_IS_NOT_VALID_FOR_USAGE"},
	{TrustNoIssuanceChainPolicy, "NO_ISSUANCE_CHAIN_POLICY"},
}

// ChainStatus is the raw CERT_TRUST_STATUS.dwErrorStatus bitmask produced by
// chain evaluation. Zero means the chain is fully trusted.
type ChainStatus uint32

// OK reports whether chain evaluation raised no complaints at all.
func (s ChainStatus) OK() bool { return s == 0 }

// Has reports whether a specific CERT_TRUST_* bit is set.
func (s ChainStatus) Has(bit uint32) bool { return uint32(s)&bit != 0 }

// Problems returns the symbolic names of every error bit that is set.
func (s ChainStatus) Problems() []string {
	if s == 0 {
		return nil
	}

	res := make([]string, 0, 2)
	for _, e := range chainStatusNames {
		if s.Has(e.bit) {
			res = append(res, e.name)
		}
	}
	return res
}

func (s ChainStatus) String() string {
	if s == 0 {
		return "ok"
	}

	problems := s.Problems()
	if len(problems) == 0 {
		return "unknown error status " + hex32(uint32(s))
	}
	return strings.Join(problems, "|")
}

func hex32(v uint32) string {
	const digits = "0123456789ABCDEF"

	buf := [10]byte{'0', 'x'}
	for i := 0; i < 8; i++ {
		buf[9-i] = digits[v&0xF]
		v >>= 4
	}
	return string(buf[:])
}

// ErrZeroCertificate is returned when BuildChain is given a zero Cert.
var ErrZeroCertificate = errors.New("csp: zero certificate")

// BuildChain builds and evaluates the certificate chain for cert using the
// default chain engine, which caches built chains and fetched CRLs for the
// lifetime of the process.
//
// extra supplies additional intermediate certificates and may be nil. When
// verifying a detached CMS signature, pass the message certificate store
// obtained from Msg.CertStore(); the issuer of the signer certificate is
// normally carried inside the message rather than installed system-wide.
//
// flags selects the revocation mode — see the RevocationCheck* constants.
// RevocationCheckChainExcludeRoot is the usual choice.
//
// A non-nil error means chain evaluation could not be performed at all. A nil
// error with a non-zero ChainStatus means the chain was evaluated and found
// wanting; inspect the status bits to tell "expired" from "revoked" from
// "untrusted root".
func BuildChain(cert Cert, extra *CertStore, flags uint32) (ChainStatus, error) {
	if cert.IsZero() {
		return 0, ErrZeroCertificate
	}

	var hExtra C.HCERTSTORE
	if extra != nil {
		hExtra = extra.hStore
	}

	var errStatus, lastErr C.DWORD

	if C.build_chain(cert.pCert, hExtra, C.DWORD(flags), &errStatus, &lastErr) == 0 {
		return 0, Error{Code: ErrorCode(lastErr), msg: "Error building certificate chain"}
	}

	return ChainStatus(errStatus), nil
}
