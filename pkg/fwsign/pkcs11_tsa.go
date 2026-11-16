package fwsign

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// PKCS#11 v3.0 Session States
const (
	CKS_UNINITIALIZED     = 0
	CKS_RO_PUBLIC_SESSION = 1
	CKS_RO_USER_FUNCTIONS = 2
	CKS_CLOSED            = 3
)

// PKCS#11 User Types
const (
	CKU_SO   = 0
	CKU_USER = 1
)

// PKCS#11 Return Codes
const (
	CKR_OK                         uint32 = 0x00000000
	CKR_PIN_INCORRECT              uint32 = 0x000000A0
	CKR_PIN_LOCKED                 uint32 = 0x000000A4
	CKR_USER_NOT_LOGGED_IN         uint32 = 0x00000101
	CKR_USER_ALREADY_LOGGED_IN     uint32 = 0x00000100
	CKR_KEY_FUNCTION_NOT_PERMITTED uint32 = 0x00000068
	CKR_SESSION_CLOSED             uint32 = 0x000000B3
	CKR_OPERATION_NOT_INITIALIZED  uint32 = 0x00000091
	CKR_CRYPTOKI_NOT_INITIALIZED   uint32 = 0x00000190
	CKR_DEVICE_ERROR               uint32 = 0x00000030
)

// HsmKeyObject models a hardware key object on the HSM token.
type HsmKeyObject struct {
	ID             string
	Label          string
	KeyType        string // "ED25519", "RSA-3072", "RSA-4096"
	CkaSensitive   bool
	CkaExtractable bool
	CkaPrivate     bool
	CkaSign        bool
	Ed25519Key     ed25519.PrivateKey
	RsaKey         *rsa.PrivateKey
}

// HsmTokenSession models an OASIS PKCS#11 v3.0 HSM session state machine.
type HsmTokenSession struct {
	mu                sync.Mutex
	State             int
	UserPin           string
	SoPin             string
	PinRetries        int
	MaxPinRetries     int
	IsPinLocked       bool
	Keys              map[string]*HsmKeyObject
	ActiveSignKeyID   string
	SessionTimeoutSec int
	LastActivity      time.Time
}

// NewHsmTokenSession initializes a hardware token session state machine.
func NewHsmTokenSession(userPin, soPin string, maxRetries int) *HsmTokenSession {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	return &HsmTokenSession{
		State:             CKS_UNINITIALIZED,
		UserPin:           userPin,
		SoPin:             soPin,
		PinRetries:        0,
		MaxPinRetries:     maxRetries,
		IsPinLocked:       false,
		Keys:              make(map[string]*HsmKeyObject),
		SessionTimeoutSec: 60,
		LastActivity:      time.Now().UTC(),
	}
}

func (s *HsmTokenSession) C_Initialize() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.State = CKS_RO_PUBLIC_SESSION
	s.LastActivity = time.Now().UTC()
	return CKR_OK
}

func (s *HsmTokenSession) C_OpenSession() (uint64, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.State == CKS_UNINITIALIZED {
		return 0, CKR_CRYPTOKI_NOT_INITIALIZED
	}
	s.State = CKS_RO_PUBLIC_SESSION
	s.LastActivity = time.Now().UTC()
	return 1001, CKR_OK
}

func (s *HsmTokenSession) C_Login(userType uint32, pin string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastActivity = time.Now().UTC()

	if s.State == CKS_UNINITIALIZED || s.State == CKS_CLOSED {
		return CKR_SESSION_CLOSED
	}

	if userType == CKU_USER {
		if s.IsPinLocked {
			return CKR_PIN_LOCKED
		}

		if pin != s.UserPin {
			s.PinRetries++
			if s.PinRetries >= s.MaxPinRetries {
				s.IsPinLocked = true
				return CKR_PIN_LOCKED
			}
			return CKR_PIN_INCORRECT
		}

		// PIN correct
		s.PinRetries = 0
		s.State = CKS_RO_USER_FUNCTIONS
		return CKR_OK
	}

	if userType == CKU_SO {
		if pin != s.SoPin {
			return CKR_PIN_INCORRECT
		}
		s.State = CKS_RO_USER_FUNCTIONS
		return CKR_OK
	}

	return CKR_PIN_INCORRECT
}

func (s *HsmTokenSession) ResetPin(soPin, newUserPin string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	if soPin != s.SoPin {
		return CKR_PIN_INCORRECT
	}
	s.UserPin = newUserPin
	s.PinRetries = 0
	s.IsPinLocked = false
	return CKR_OK
}

func (s *HsmTokenSession) AddKey(key *HsmKeyObject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if key != nil && key.ID != "" {
		s.Keys[key.ID] = key
	}
}

func (s *HsmTokenSession) C_SignInit(keyID string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastActivity = time.Now().UTC()

	if s.State != CKS_RO_USER_FUNCTIONS {
		return CKR_USER_NOT_LOGGED_IN
	}

	key, exists := s.Keys[keyID]
	if !exists {
		return CKR_OPERATION_NOT_INITIALIZED
	}

	// Security Invariants: CKA_SENSITIVE must be true, CKA_EXTRACTABLE must be false, CKA_SIGN must be true
	if !key.CkaSign || !key.CkaSensitive || key.CkaExtractable {
		return CKR_KEY_FUNCTION_NOT_PERMITTED
	}

	s.ActiveSignKeyID = keyID
	return CKR_OK
}

func (s *HsmTokenSession) C_Sign(digest []byte) ([]byte, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.LastActivity = time.Now().UTC()

	if s.State != CKS_RO_USER_FUNCTIONS {
		return nil, CKR_USER_NOT_LOGGED_IN
	}
	if s.ActiveSignKeyID == "" {
		return nil, CKR_OPERATION_NOT_INITIALIZED
	}

	key := s.Keys[s.ActiveSignKeyID]
	if key == nil {
		return nil, CKR_DEVICE_ERROR
	}

	if key.KeyType == "ED25519" && key.Ed25519Key != nil {
		sig := ed25519.Sign(key.Ed25519Key, digest)
		return sig, CKR_OK
	}

	if (key.KeyType == "RSA-3072" || key.KeyType == "RSA-4096") && key.RsaKey != nil {
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA384,
		}
		sig, err := rsa.SignPSS(rand.Reader, key.RsaKey, crypto.SHA384, digest, pssOpts)
		if err != nil {
			return nil, CKR_DEVICE_ERROR
		}
		return sig, CKR_OK
	}

	return nil, CKR_KEY_FUNCTION_NOT_PERMITTED
}

func (s *HsmTokenSession) C_Logout() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ActiveSignKeyID = ""
	s.State = CKS_RO_PUBLIC_SESSION
	s.LastActivity = time.Now().UTC()
	return CKR_OK
}

func (s *HsmTokenSession) C_CloseSession() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ActiveSignKeyID = ""
	s.State = CKS_CLOSED
	return CKR_OK
}

// ----------------------------------------------------------------------------
// RFC 3161 Cryptographic Time-Stamp Authority (TSA) Engine
// ----------------------------------------------------------------------------

// TimeStampToken represents an RFC 3161 Time-Stamp Token (TSTInfo).
type TimeStampToken struct {
	SerialNumber string    `json:"serial_number"`
	PolicyOID    string    `json:"policy_oid"`
	ImprintHex   string    `json:"imprint_hex"`
	NonceHex     string    `json:"nonce_hex"`
	GenTimeUTC   time.Time `json:"gen_time_utc"`
	TsaCertPEM   string    `json:"tsa_cert_pem"`
	SignatureHex string    `json:"signature_hex"`
}

// TsaAuthority encapsulates the signing key and certificate of a Time-Stamp Authority.
type TsaAuthority struct {
	Key     ed25519.PrivateKey
	Cert    *x509.Certificate
	CertPEM string
}

// NewTsaAuthority initializes an in-memory RFC 3161 Time-Stamp Authority.
func NewTsaAuthority() (*TsaAuthority, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, serialLimit)

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Logihertz Sovereign Time-Stamp Authority",
			Organization: []string{"Logihertz Systems (OPC) Private Limited"},
			Country:      []string{"IN"},
		},
		NotBefore: now.Add(-1 * time.Hour),
		NotAfter:  now.Add(3650 * 24 * time.Hour), // 10 years
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageTimeStamping,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("create tsa cert: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse tsa cert: %w", err)
	}

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	return &TsaAuthority{
		Key:     priv,
		Cert:    cert,
		CertPEM: certPEM,
	}, nil
}

// ComputeTsaImprint computes SHA-256("LH_RFC3161_IMPRINT:" || signature || imageDigest || nonce)
func ComputeTsaImprint(signature, imageDigest, nonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte("LH_RFC3161_IMPRINT:"))
	h.Write(signature)
	h.Write(imageDigest)
	h.Write(nonce)
	return h.Sum(nil)
}

// GenerateTimestampToken creates and signs an RFC 3161 Time-Stamp Token.
func GenerateTimestampToken(
	signature []byte,
	imageDigest []byte,
	nonce []byte,
	tsa *TsaAuthority,
	genTime time.Time,
) (*TimeStampToken, error) {
	if tsa == nil {
		return nil, errors.New("nil tsa authority")
	}
	if genTime.IsZero() {
		genTime = time.Now().UTC()
	}

	imprint := ComputeTsaImprint(signature, imageDigest, nonce)
	imprintHex := hex.EncodeToString(imprint)
	nonceHex := hex.EncodeToString(nonce)

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 64)
	sn, _ := rand.Int(rand.Reader, serialLimit)
	serialStr := fmt.Sprintf("%016X", sn)

	policyOID := "1.3.6.1.4.1.58999.1.1" // Logihertz Sovereign Firmware Time-Stamp Policy OID

	// Canonical payload for TSA signature
	dataToSign := fmt.Sprintf("%s|%s|%s|%s|%d", serialStr, policyOID, imprintHex, nonceHex, genTime.Unix())
	dataDigest := sha256.Sum256([]byte(dataToSign))

	tokenSig := ed25519.Sign(tsa.Key, dataDigest[:])

	return &TimeStampToken{
		SerialNumber: serialStr,
		PolicyOID:    policyOID,
		ImprintHex:   imprintHex,
		NonceHex:     nonceHex,
		GenTimeUTC:   genTime,
		TsaCertPEM:   tsa.CertPEM,
		SignatureHex: hex.EncodeToString(tokenSig),
	}, nil
}

// VerifyTimestampToken validates the cryptographic integrity and message imprint of a TimeStampToken.
func VerifyTimestampToken(
	token *TimeStampToken,
	signature []byte,
	imageDigest []byte,
	tsaCert *x509.Certificate,
) error {
	if token == nil {
		return errors.New("nil timestamp token")
	}

	nonce, err := hex.DecodeString(token.NonceHex)
	if err != nil {
		return fmt.Errorf("invalid nonce hex: %w", err)
	}

	// 1. Recompute and verify Message Imprint
	expectedImprint := ComputeTsaImprint(signature, imageDigest, nonce)
	tokenImprint, err := hex.DecodeString(token.ImprintHex)
	if err != nil {
		return fmt.Errorf("invalid imprint hex: %w", err)
	}

	if subtle.ConstantTimeCompare(expectedImprint, tokenImprint) != 1 {
		return errors.New("RFC 3161 message imprint mismatch (signature or image digest modified)")
	}

	// 2. Resolve TSA Certificate
	if tsaCert == nil {
		if token.TsaCertPEM == "" {
			return errors.New("missing TSA certificate")
		}
		block, _ := pem.Decode([]byte(token.TsaCertPEM))
		if block == nil {
			return errors.New("failed to decode TSA certificate PEM")
		}
		var err error
		tsaCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse TSA cert: %w", err)
		}
	}

	// 3. Verify TSA Signature
	tsaPub, ok := tsaCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("TSA public key is not Ed25519")
	}

	sigBytes, err := hex.DecodeString(token.SignatureHex)
	if err != nil {
		return fmt.Errorf("invalid TSA signature hex: %w", err)
	}

	dataToSign := fmt.Sprintf("%s|%s|%s|%s|%d", token.SerialNumber, token.PolicyOID, token.ImprintHex, token.NonceHex, token.GenTimeUTC.Unix())
	dataDigest := sha256.Sum256([]byte(dataToSign))

	if !ed25519.Verify(tsaPub, dataDigest[:], sigBytes) {
		return errors.New("RFC 3161 TSA signature verification failed")
	}

	return nil
}
