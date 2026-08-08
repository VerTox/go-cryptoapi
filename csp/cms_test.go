//go:build linux

package csp

import (
	"errors"
	"strings"
	"testing"
)

func TestCMSVerification_OK(t *testing.T) {
	for _, tc := range []struct {
		name string
		v    CMSVerification
		want bool
	}{
		{"no signers", CMSVerification{}, false},
		{"single good signer", CMSVerification{Signers: []SignerVerification{{}}}, true},
		{
			"single signer with bad chain",
			CMSVerification{Signers: []SignerVerification{
				{ChainStatus: ChainStatus(TrustIsRevoked)},
			}},
			false,
		},
		{
			"one good, one bad — message is not OK",
			CMSVerification{Signers: []SignerVerification{
				{Index: 0},
				{Index: 1, SignatureErr: errors.New("bad signature")},
			}},
			false,
		},
		{
			"all signers good",
			CMSVerification{Signers: []SignerVerification{{Index: 0}, {Index: 1}}},
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.v.OK(); got != tc.want {
				t.Errorf("OK() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSignerVerification_Reason(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    SignerVerification
		want string
	}{
		{"passed", SignerVerification{}, ""},
		{
			"signature error wins over chain status",
			SignerVerification{
				SignatureErr: errors.New("bad signature"),
				ChainStatus:  ChainStatus(TrustIsRevoked),
			},
			"bad signature",
		},
		{
			"chain status reported when signature is fine",
			SignerVerification{ChainStatus: ChainStatus(TrustIsNotTimeValid)},
			"IS_NOT_TIME_VALID",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.Reason(); got != tc.want {
				t.Errorf("Reason() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCMSVerification_ReasonListsEverySigner(t *testing.T) {
	v := CMSVerification{Signers: []SignerVerification{
		{Index: 0},
		{Index: 1, ChainStatus: ChainStatus(TrustIsRevoked)},
		{Index: 2, SignatureErr: errors.New("bad signature")},
	}}

	got := v.Reason()
	if !strings.Contains(got, "signer 1") || !strings.Contains(got, "signer 2") {
		t.Errorf("Reason() = %q, want it to mention signers 1 and 2", got)
	}
	if strings.Contains(got, "signer 0") {
		t.Errorf("Reason() = %q, must not mention the signer that passed", got)
	}
}

func TestVerifyDetachedCMS_EmptyInput(t *testing.T) {
	for _, tc := range []struct {
		name      string
		data, sig []byte
	}{
		{"no data", nil, []byte{1}},
		{"no signature", []byte{1}, nil},
		{"neither", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyDetachedCMS(tc.data, tc.sig); !errors.Is(err, ErrEmptyInput) {
				t.Errorf("error = %v, want ErrEmptyInput", err)
			}
		})
	}
}

func TestVerifyDetachedCMS_GoodSignature(t *testing.T) {
	data := loadFixture(t, "testdata/good.xml")
	sig := loadFixture(t, "testdata/good.xml.sig")

	res, err := VerifyDetachedCMS(data, sig)
	if err != nil {
		t.Fatalf("VerifyDetachedCMS: %v", err)
	}
	if !res.OK() {
		t.Fatalf("verification failed: %s", res.Reason())
	}
	if len(res.Signers) == 0 {
		t.Fatal("no signers reported")
	}

	s := res.Signers[0]
	if s.NotBefore.IsZero() || s.NotAfter.IsZero() {
		t.Errorf("certificate validity not populated: %v .. %v", s.NotBefore, s.NotAfter)
	}
	if !s.NotBefore.Before(s.NotAfter) {
		t.Errorf("NotBefore %v is not before NotAfter %v", s.NotBefore, s.NotAfter)
	}
}

func TestVerifyDetachedCMS_ExpiredCertificate(t *testing.T) {
	data := loadFixture(t, "testdata/expired.xml")
	sig := loadFixture(t, "testdata/expired.xml.sig")

	res, err := VerifyDetachedCMS(data, sig)
	if err != nil {
		t.Fatalf("VerifyDetachedCMS: %v", err)
	}
	if res.OK() {
		t.Fatal("an expired certificate was accepted")
	}
	if !res.Signers[0].ChainStatus.Has(TrustIsNotTimeValid) {
		t.Errorf("chain status = %v, want IS_NOT_TIME_VALID", res.Signers[0].ChainStatus)
	}
}

// TestVerifyDetachedCMS_TamperedData is the check that matters most: altering
// the signed payload must be detected as a signature mismatch, not merely as a
// chain problem.
func TestVerifyDetachedCMS_TamperedData(t *testing.T) {
	data := loadFixture(t, "testdata/good.xml")
	sig := loadFixture(t, "testdata/good.xml.sig")

	tampered := make([]byte, len(data))
	copy(tampered, data)
	tampered[len(tampered)/2]++

	res, err := VerifyDetachedCMS(tampered, sig)
	if err != nil {
		t.Fatalf("VerifyDetachedCMS: %v", err)
	}
	if res.OK() {
		t.Fatal("tampered data was accepted")
	}
	if res.Signers[0].SignatureErr == nil {
		t.Errorf("expected a signature error, got chain status %v", res.Signers[0].ChainStatus)
	}
}

func TestVerifyDetachedCMS_WithSignerNames(t *testing.T) {
	data := loadFixture(t, "testdata/good.xml")
	sig := loadFixture(t, "testdata/good.xml.sig")

	res, err := VerifyDetachedCMS(data, sig, WithSignerNames())
	if err != nil {
		t.Fatalf("VerifyDetachedCMS: %v", err)
	}
	if res.Signers[0].Issuer == "" {
		t.Error("Issuer not populated with WithSignerNames")
	}
	if res.Signers[0].Subject == "" {
		t.Error("Subject not populated with WithSignerNames")
	}

	plain, err := VerifyDetachedCMS(data, sig)
	if err != nil {
		t.Fatalf("VerifyDetachedCMS: %v", err)
	}
	if plain.Signers[0].Issuer != "" {
		t.Error("Issuer populated without WithSignerNames")
	}
}

func TestVerifyDetachedCMS_WithoutRevocation(t *testing.T) {
	data := loadFixture(t, "testdata/good.xml")
	sig := loadFixture(t, "testdata/good.xml.sig")

	res, err := VerifyDetachedCMS(data, sig, WithoutRevocation())
	if err != nil {
		t.Fatalf("VerifyDetachedCMS: %v", err)
	}
	if !res.OK() {
		t.Fatalf("verification failed without revocation: %s", res.Reason())
	}
}

func BenchmarkVerifyDetachedCMS(b *testing.B) {
	data := loadFixture(b, "testdata/good.xml")
	sig := loadFixture(b, "testdata/good.xml.sig")

	// Warm the chain engine so the first iteration does not pay the CRL fetch.
	if _, err := VerifyDetachedCMS(data, sig); err != nil {
		b.Fatalf("warm-up: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		res, err := VerifyDetachedCMS(data, sig)
		if err != nil || !res.OK() {
			b.Fatalf("verify failed: err=%v reason=%s", err, res.Reason())
		}
	}
}

func BenchmarkVerifyDetachedCMSParallel(b *testing.B) {
	data := loadFixture(b, "testdata/good.xml")
	sig := loadFixture(b, "testdata/good.xml.sig")

	if _, err := VerifyDetachedCMS(data, sig); err != nil {
		b.Fatalf("warm-up: %v", err)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			res, err := VerifyDetachedCMS(data, sig)
			if err != nil || !res.OK() {
				b.Fatalf("verify failed: err=%v reason=%s", err, res.Reason())
			}
		}
	})
}
