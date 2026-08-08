//go:build linux

package csp

/*
#include "common.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Errors returned by VerifyDetachedCMS when verification cannot be carried out
// at all, as opposed to completing with a negative verdict.
var (
	// ErrEmptyInput is returned when data or signature is empty.
	ErrEmptyInput = errors.New("csp: empty data or signature")
	// ErrNoSigners is returned when the CMS message carries no SignerInfo.
	ErrNoSigners = errors.New("csp: message contains no signers")
)

// CMSVerifyOption configures VerifyDetachedCMS.
type CMSVerifyOption func(*cmsVerifyConfig)

type cmsVerifyConfig struct {
	revocationFlags uint32
	collectNames    bool
}

// WithRevocationMode selects how revocation is checked while evaluating the
// signer's certificate chain. Pass one of the RevocationCheck* constants,
// optionally combined with RevocationCheckCacheOnly.
//
// The default is RevocationCheckChainExcludeRoot, which mirrors
// `cryptcp -verify -errchain`.
func WithRevocationMode(flags uint32) CMSVerifyOption {
	return func(c *cmsVerifyConfig) { c.revocationFlags = flags }
}

// WithoutRevocation skips revocation checking entirely. The chain is still
// built and its trust anchor, validity dates and signatures are evaluated.
func WithoutRevocation() CMSVerifyOption {
	return func(c *cmsVerifyConfig) { c.revocationFlags = RevocationCheckNone }
}

// WithSignerNames makes VerifyDetachedCMS populate Subject and Issuer on every
// SignerVerification. Off by default: rendering X.509 names costs a little and
// most callers only need the verdict.
func WithSignerNames() CMSVerifyOption {
	return func(c *cmsVerifyConfig) { c.collectNames = true }
}

// SignerVerification is the outcome for a single SignerInfo in a CMS message.
type SignerVerification struct {
	// Index is the position of this SignerInfo in the message.
	Index int
	// Subject and Issuer are populated only when WithSignerNames is used.
	Subject string
	Issuer  string
	// NotBefore and NotAfter are the signer certificate's validity bounds.
	NotBefore time.Time
	NotAfter  time.Time
	// SignatureErr is non-nil when the signature itself does not match the
	// data, or when the signer certificate could not be located.
	SignatureErr error
	// ChainStatus describes the outcome of chain evaluation. It is only
	// meaningful when SignatureErr is nil.
	ChainStatus ChainStatus
	// ChainErr is non-nil when chain evaluation could not be performed.
	ChainErr error
}

// OK reports whether this signer passed every check.
func (s SignerVerification) OK() bool {
	return s.SignatureErr == nil && s.ChainErr == nil && s.ChainStatus.OK()
}

// Reason returns a short human-readable explanation of why this signer failed,
// or an empty string when it passed.
func (s SignerVerification) Reason() string {
	switch {
	case s.SignatureErr != nil:
		return s.SignatureErr.Error()
	case s.ChainErr != nil:
		return s.ChainErr.Error()
	case !s.ChainStatus.OK():
		return s.ChainStatus.String()
	default:
		return ""
	}
}

// CMSVerification aggregates the per-signer outcomes of a CMS verification.
type CMSVerification struct {
	Signers []SignerVerification
}

// OK reports whether every signer in the message passed every check. A message
// with no signers is never OK.
//
// Requiring all signers to be valid matches what `cryptcp -verify` does: it
// fails if any signature in the file is bad.
func (v CMSVerification) OK() bool {
	if len(v.Signers) == 0 {
		return false
	}

	for _, s := range v.Signers {
		if !s.OK() {
			return false
		}
	}
	return true
}

// Reason returns a description of every signer that failed, or an empty string
// when the message is fully valid.
func (v CMSVerification) Reason() string {
	if len(v.Signers) == 0 {
		return ErrNoSigners.Error()
	}

	problems := make([]string, 0, len(v.Signers))
	for _, s := range v.Signers {
		if r := s.Reason(); r != "" {
			problems = append(problems, fmt.Sprintf("signer %d: %s", s.Index, r))
		}
	}
	return strings.Join(problems, "; ")
}

// VerifyDetachedCMS verifies a detached PKCS#7/CMS signature over data.
//
// Every SignerInfo in the message is checked: the signature itself against the
// signer certificate, then that certificate's chain up to a trusted root in the
// system stores, including revocation. Chain evaluation goes through the
// default chain engine, which caches built chains and fetched CRLs for the
// lifetime of the process — repeat verifications against the same CA are
// therefore cheap.
//
// A non-nil error means verification could not be performed: malformed input,
// an unreadable message, or a failure inside CryptoAPI. A nil error means the
// message was examined and the verdict is in the result — check OK().
func VerifyDetachedCMS(data, sig []byte, opts ...CMSVerifyOption) (*CMSVerification, error) {
	if len(data) == 0 || len(sig) == 0 {
		return nil, ErrEmptyInput
	}

	cfg := cmsVerifyConfig{revocationFlags: RevocationCheckChainExcludeRoot}
	for _, o := range opts {
		o(&cfg)
	}

	msg, err := OpenToVerify(sig)
	if err != nil {
		return nil, fmt.Errorf("open message: %w", err)
	}
	defer func() {
		if closeErr := msg.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close message: %w", closeErr)
		}
	}()

	if _, err = msg.Write(data); err != nil {
		return nil, fmt.Errorf("supply signed data: %w", err)
	}

	store, err := msg.CertStore()
	if err != nil {
		return nil, fmt.Errorf("message certificate store: %w", err)
	}
	defer func() { _ = store.Close() }()

	count, err := msg.GetSignerCount()
	if err != nil {
		return nil, fmt.Errorf("signer count: %w", err)
	}
	if count <= 0 {
		return nil, ErrNoSigners
	}

	res := &CMSVerification{Signers: make([]SignerVerification, 0, count)}
	for i := 0; i < count; i++ {
		res.Signers = append(res.Signers, verifySigner(msg, store, i, cfg))
	}

	return res, nil
}

// verifySigner checks one SignerInfo. It never returns an error: everything is
// recorded in the SignerVerification so that a bad signer does not mask the
// results for the others.
func verifySigner(msg *Msg, store CertStore, i int, cfg cmsVerifyConfig) SignerVerification {
	out := SignerVerification{Index: i}

	cert, err := msg.GetSignerCert(i, store)
	if err != nil {
		out.SignatureErr = fmt.Errorf("locate signer certificate: %w", err)
		return out
	}
	if cert.IsZero() {
		out.SignatureErr = errors.New("signer certificate not found in message")
		return out
	}
	defer func() { _ = cert.Close() }()

	info := cert.Info()
	out.NotBefore = fileTimeToTime(info.pCertInfo.NotBefore)
	out.NotAfter = fileTimeToTime(info.pCertInfo.NotAfter)

	if cfg.collectNames {
		if s, nameErr := info.SubjectStr(); nameErr == nil {
			out.Subject = s
		}
		if s, nameErr := info.IssuerStr(); nameErr == nil {
			out.Issuer = s
		}
	}

	if err = msg.Verify(cert); err != nil {
		out.SignatureErr = err
		return out
	}

	out.ChainStatus, out.ChainErr = BuildChain(cert, &store, cfg.revocationFlags)

	return out
}
