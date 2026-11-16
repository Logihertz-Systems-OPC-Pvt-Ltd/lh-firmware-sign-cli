package fwsign

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const (
	TrailerMagic = "LHFWSIG1"
	TrailerVer   = 1
)

// FirmwareHeaderV1 encapsulates the authenticated metadata envelope for firmware signing.
type FirmwareHeaderV1 struct {
	Magic            string `json:"magic"`
	FormatVersion    uint32 `json:"format_version"`
	SVN              uint32 `json:"svn"`
	HardwareCompatID string `json:"hardware_compat_id"`
	ImageSize        uint64 `json:"image_size"`
	ImageSHA256      string `json:"image_sha256"`
	ImageSHA384      string `json:"image_sha384"`
}

// CanonicalBytes returns the deterministic binary representation of the header.
func (h *FirmwareHeaderV1) CanonicalBytes() []byte {
	hwBytes := []byte(h.HardwareCompatID)
	raw256, _ := hex.DecodeString(h.ImageSHA256)
	raw384, _ := hex.DecodeString(h.ImageSHA384)

	buf := new(bytes.Buffer)
	buf.WriteString(TrailerMagic)
	_ = binary.Write(buf, binary.BigEndian, h.FormatVersion)
	_ = binary.Write(buf, binary.BigEndian, h.SVN)
	_ = binary.Write(buf, binary.BigEndian, uint32(len(hwBytes)))
	buf.Write(hwBytes)
	_ = binary.Write(buf, binary.BigEndian, h.ImageSize)

	if len(raw256) == 32 {
		buf.Write(raw256)
	} else {
		buf.Write(make([]byte, 32))
	}
	if len(raw384) == 48 {
		buf.Write(raw384)
	} else {
		buf.Write(make([]byte, 48))
	}
	return buf.Bytes()
}

// ComputeSigningPreimage computes M_sign = SHA-384("LH_FW_SIGN_V1:" || CanonicalHeader || ImageSHA256 || ImageSHA384)
func ComputeSigningPreimage(h *FirmwareHeaderV1) []byte {
	canonicalHdr := h.CanonicalBytes()
	raw256, _ := hex.DecodeString(h.ImageSHA256)
	raw384, _ := hex.DecodeString(h.ImageSHA384)

	h384 := sha512.New384()
	h384.Write([]byte("LH_FW_SIGN_V1:"))
	h384.Write(canonicalHdr)
	h384.Write(raw256)
	h384.Write(raw384)
	return h384.Sum(nil)
}

// SignedFirmwareReceipt represents the complete cryptographic receipt of a signed firmware.
type SignedFirmwareReceipt struct {
	Header              FirmwareHeaderV1 `json:"header"`
	PreimageDigest      string           `json:"preimage_digest"`
	SignatureEd25519    string           `json:"signature_ed25519"`
	SignatureRsaPss     string           `json:"signature_rsa_pss"`
	PublicKeyEd25519    string           `json:"public_key_ed25519"`
	CertificateChainPEM []string         `json:"certificate_chain_pem"`
	TimestampToken      *TimeStampToken  `json:"timestamp_token,omitempty"`
	CreatedAt           string           `json:"created_at"`
}

// GenerateCodeSigningCAAndLeaf generates an in-memory Code Signing Root CA and Leaf Certificate.
func GenerateCodeSigningCAAndLeaf(validityDays int) (
	caKey *rsa.PrivateKey, caCert *x509.Certificate,
	leafKey *rsa.PrivateKey, leafCert *x509.Certificate,
	caPEM, leafPEM string, err error,
) {
	if validityDays <= 0 {
		validityDays = 365
	}

	caKey, err = rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, nil, nil, "", "", fmt.Errorf("generate CA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	caSerial, _ := rand.Int(rand.Reader, serialNumberLimit)

	now := time.Now().UTC()
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "Logihertz Sovereign Firmware Root CA",
			Organization: []string{"Logihertz Systems (OPC) Private Limited"},
			Country:      []string{"IN"},
		},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(time.Duration(validityDays*5) * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, "", "", fmt.Errorf("create CA cert: %w", err)
	}
	caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		return nil, nil, nil, nil, "", "", fmt.Errorf("parse CA cert: %w", err)
	}

	leafKey, err = rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, nil, nil, "", "", fmt.Errorf("generate leaf key: %w", err)
	}

	leafSerial, _ := rand.Int(rand.Reader, serialNumberLimit)
	leafTemplate := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName:   "Logihertz Industrial Firmware Signer",
			Organization: []string{"Logihertz Systems (OPC) Private Limited"},
			Country:      []string{"IN"},
		},
		NotBefore:   now.Add(-1 * time.Hour),
		NotAfter:    now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, nil, "", "", fmt.Errorf("create leaf cert: %w", err)
	}
	leafCert, err = x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, nil, nil, "", "", fmt.Errorf("parse leaf cert: %w", err)
	}

	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	leafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	return caKey, caCert, leafKey, leafCert, caPEM, leafPEM, nil
}

// VerifyCodeSigningCertChain validates the leaf certificate against the root CA,
// enforcing Extended Key Usage for Code Signing and long-term timestamped validity.
func VerifyCodeSigningCertChain(leafCert, rootCert *x509.Certificate, tsTime time.Time) error {
	if leafCert == nil || rootCert == nil {
		return errors.New("missing leaf or root certificate")
	}

	// Verify Code Signing EKU
	hasCodeSigning := false
	for _, eku := range leafCert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageCodeSigning || eku == x509.ExtKeyUsageAny {
			hasCodeSigning = true
			break
		}
	}
	if !hasCodeSigning {
		return errors.New("leaf certificate missing ExtKeyUsageCodeSigning (1.3.6.1.5.5.7.3.3)")
	}

	// Verify Signature Chain
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	checkTime := time.Now().UTC()
	if !tsTime.IsZero() {
		checkTime = tsTime
	}

	opts := x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		CurrentTime: checkTime,
	}

	if _, err := leafCert.Verify(opts); err != nil {
		return fmt.Errorf("certificate chain verification failed at check time %s: %w", checkTime.Format(time.RFC3339), err)
	}

	return nil
}

// SignFirmware creates a dual-signature (Ed25519 + RSA-PSS) SignedFirmwareReceipt.
func SignFirmware(
	firmwareBytes []byte,
	svn uint32,
	hwID string,
	edKey ed25519.PrivateKey,
	rsaKey *rsa.PrivateKey,
	certChainPEM []string,
	tsa *TsaAuthority,
) (*SignedFirmwareReceipt, error) {
	if len(firmwareBytes) == 0 {
		return nil, errors.New("empty firmware image")
	}
	if svn == 0 {
		return nil, errors.New("svn must be >= 1")
	}
	if hwID == "" {
		hwID = "default-hardware"
	}

	s256 := sha256.Sum256(firmwareBytes)
	s384 := sha512.Sum384(firmwareBytes)

	header := FirmwareHeaderV1{
		Magic:            TrailerMagic,
		FormatVersion:    TrailerVer,
		SVN:              svn,
		HardwareCompatID: hwID,
		ImageSize:        uint64(len(firmwareBytes)),
		ImageSHA256:      hex.EncodeToString(s256[:]),
		ImageSHA384:      hex.EncodeToString(s384[:]),
	}

	preimage := ComputeSigningPreimage(&header)

	// 1. Primary Signature: Ed25519
	edSig := ed25519.Sign(edKey, preimage)
	edPub := edKey.Public().(ed25519.PublicKey)

	// 2. Secondary Signature: RSA-PSS-SHA384 with salt length == hash length (48)
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA384,
	}
	rsaSig, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA384, preimage, pssOpts)
	if err != nil {
		return nil, fmt.Errorf("rsa-pss sign failed: %w", err)
	}

	combinedSigs := append(edSig, rsaSig...)

	receipt := &SignedFirmwareReceipt{
		Header:              header,
		PreimageDigest:      hex.EncodeToString(preimage),
		SignatureEd25519:    hex.EncodeToString(edSig),
		SignatureRsaPss:     hex.EncodeToString(rsaSig),
		PublicKeyEd25519:    hex.EncodeToString(edPub),
		CertificateChainPEM: certChainPEM,
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
	}

	// 3. RFC 3161 Timestamp Token
	if tsa != nil {
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			return nil, fmt.Errorf("read nonce: %w", err)
		}
		tsToken, err := GenerateTimestampToken(combinedSigs, s256[:], nonce, tsa, time.Now().UTC())
		if err != nil {
			return nil, fmt.Errorf("generate tsa token: %w", err)
		}
		receipt.TimestampToken = tsToken
	}

	return receipt, nil
}

// VerifyFirmwareReceipt validates the integrity, anti-rollback SVN, hardware ID,
// dual signatures (Ed25519 + RSA-PSS), X.509 cert chain, and RFC 3161 timestamp.
func VerifyFirmwareReceipt(
	firmwareBytes []byte,
	receipt *SignedFirmwareReceipt,
	minSVN uint32,
	expectedHwID string,
	rootCert *x509.Certificate,
	tsaCert *x509.Certificate,
) error {
	if receipt == nil {
		return errors.New("nil receipt")
	}

	// 1. Image Size & Hash Verification
	if uint64(len(firmwareBytes)) != receipt.Header.ImageSize {
		return fmt.Errorf("image size mismatch: got %d, expected %d", len(firmwareBytes), receipt.Header.ImageSize)
	}
	s256 := sha256.Sum256(firmwareBytes)
	s384 := sha512.Sum384(firmwareBytes)

	if hex.EncodeToString(s256[:]) != receipt.Header.ImageSHA256 {
		return errors.New("image SHA-256 digest mismatch (firmware tampered)")
	}
	if hex.EncodeToString(s384[:]) != receipt.Header.ImageSHA384 {
		return errors.New("image SHA-384 digest mismatch (firmware tampered)")
	}

	// 2. Anti-Rollback SVN Check
	if receipt.Header.SVN < minSVN {
		return fmt.Errorf("anti-rollback check failed: receipt SVN %d < minimum required SVN %d", receipt.Header.SVN, minSVN)
	}

	// 3. Hardware Compatibility Check
	if expectedHwID != "" && receipt.Header.HardwareCompatID != expectedHwID {
		return fmt.Errorf("hardware compatibility ID mismatch: got '%s', expected '%s'", receipt.Header.HardwareCompatID, expectedHwID)
	}

	// 4. Preimage Verification
	preimage := ComputeSigningPreimage(&receipt.Header)
	if hex.EncodeToString(preimage) != receipt.PreimageDigest {
		return errors.New("preimage digest mismatch in receipt")
	}

	// 5. Ed25519 Signature Verification
	edPubBytes, err := hex.DecodeString(receipt.PublicKeyEd25519)
	if err != nil || len(edPubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key in receipt")
	}
	edSigBytes, err := hex.DecodeString(receipt.SignatureEd25519)
	if err != nil || len(edSigBytes) != ed25519.SignatureSize {
		return errors.New("invalid Ed25519 signature in receipt")
	}
	if !ed25519.Verify(ed25519.PublicKey(edPubBytes), preimage, edSigBytes) {
		return errors.New("Ed25519 signature verification failed")
	}

	// 6. Parse X.509 Certificate Chain
	if len(receipt.CertificateChainPEM) == 0 {
		return errors.New("missing certificate chain in receipt")
	}
	leafBlock, _ := pem.Decode([]byte(receipt.CertificateChainPEM[0]))
	if leafBlock == nil {
		return errors.New("failed to decode leaf certificate PEM")
	}
	leafCert, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse leaf certificate: %w", err)
	}

	rsaPub, ok := leafCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("leaf certificate public key is not RSA")
	}

	// 7. RSA-PSS Signature Verification
	rsaSigBytes, err := hex.DecodeString(receipt.SignatureRsaPss)
	if err != nil {
		return errors.New("invalid RSA-PSS signature hex in receipt")
	}
	pssOpts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA384,
	}
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA384, preimage, rsaSigBytes, pssOpts); err != nil {
		return fmt.Errorf("RSA-PSS signature verification failed: %w", err)
	}

	// 8. RFC 3161 Timestamp Token Verification
	var tsTime time.Time
	if receipt.TimestampToken != nil {
		if tsaCert == nil && receipt.TimestampToken.TsaCertPEM != "" {
			tsaBlock, _ := pem.Decode([]byte(receipt.TimestampToken.TsaCertPEM))
			if tsaBlock != nil {
				tsaCert, _ = x509.ParseCertificate(tsaBlock.Bytes)
			}
		}
		combinedSigs := append(edSigBytes, rsaSigBytes...)
		if err := VerifyTimestampToken(receipt.TimestampToken, combinedSigs, s256[:], tsaCert); err != nil {
			return fmt.Errorf("RFC 3161 timestamp token invalid: %w", err)
		}
		tsTime = receipt.TimestampToken.GenTimeUTC
	} else {
		return errors.New("missing required RFC 3161 timestamp token")
	}

	// 9. Certificate Chain Verification with Verified Timestamp
	if rootCert == nil && len(receipt.CertificateChainPEM) > 1 {
		rootBlock, _ := pem.Decode([]byte(receipt.CertificateChainPEM[len(receipt.CertificateChainPEM)-1]))
		if rootBlock != nil {
			rootCert, _ = x509.ParseCertificate(rootBlock.Bytes)
		}
	}
	if err := VerifyCodeSigningCertChain(leafCert, rootCert, tsTime); err != nil {
		return fmt.Errorf("code-signing certificate chain invalid: %w", err)
	}

	return nil
}

// EncodeTrailer serializes a binary trailer LHFWSIG1.
func EncodeTrailer(receipt *SignedFirmwareReceipt) ([]byte, error) {
	if receipt == nil {
		return nil, errors.New("nil receipt")
	}
	receiptJSON, err := json.Marshal(receipt)
	if err != nil {
		return nil, fmt.Errorf("marshal receipt JSON: %w", err)
	}

	buf := new(bytes.Buffer)
	buf.WriteString(TrailerMagic)
	_ = binary.Write(buf, binary.BigEndian, uint32(TrailerVer))
	_ = binary.Write(buf, binary.BigEndian, uint32(len(receiptJSON)))
	buf.Write(receiptJSON)

	// Trailer total length (header 8 + 4 + 4 + len(receiptJSON) + len field 4 + end magic 8)
	totalLen := uint32(8 + 4 + 4 + len(receiptJSON) + 4 + 8)
	_ = binary.Write(buf, binary.BigEndian, totalLen)
	buf.WriteString(TrailerMagic)

	return buf.Bytes(), nil
}

// AttachTrailer appends a binary LHFWSIG1 trailer to firmware bytes.
func AttachTrailer(firmwareBytes []byte, receipt *SignedFirmwareReceipt) ([]byte, error) {
	trailer, err := EncodeTrailer(receipt)
	if err != nil {
		return nil, err
	}
	return append(firmwareBytes, trailer...), nil
}

// ExtractTrailer parses and separates firmware image bytes from an attached LHFWSIG1 trailer.
func ExtractTrailer(firmwareWithTrailer []byte) ([]byte, *SignedFirmwareReceipt, error) {
	if len(firmwareWithTrailer) < 28 { // 8 + 4 + 4 + 0 + 4 + 8
		return nil, nil, errors.New("data too short for trailer")
	}

	// Check end magic
	endMagic := string(firmwareWithTrailer[len(firmwareWithTrailer)-8:])
	if endMagic != TrailerMagic {
		return nil, nil, errors.New("missing trailer end magic")
	}

	// Read total length from 12 bytes before end
	lenOffset := len(firmwareWithTrailer) - 12
	totalLen := binary.BigEndian.Uint32(firmwareWithTrailer[lenOffset : lenOffset+4])
	if totalLen > uint32(len(firmwareWithTrailer)) || totalLen < 28 {
		return nil, nil, errors.New("invalid trailer length descriptor")
	}

	trailerStart := len(firmwareWithTrailer) - int(totalLen)
	trailerBytes := firmwareWithTrailer[trailerStart:]

	// Check start magic
	startMagic := string(trailerBytes[:8])
	if startMagic != TrailerMagic {
		return nil, nil, errors.New("missing trailer start magic")
	}

	jsonLen := binary.BigEndian.Uint32(trailerBytes[12:16])
	if 16+int(jsonLen)+12 != len(trailerBytes) {
		return nil, nil, errors.New("trailer JSON length mismatch")
	}

	jsonData := trailerBytes[16 : 16+jsonLen]
	var receipt SignedFirmwareReceipt
	if err := json.Unmarshal(jsonData, &receipt); err != nil {
		return nil, nil, fmt.Errorf("unmarshal trailer receipt: %w", err)
	}

	firmwareBytes := firmwareWithTrailer[:trailerStart]
	return firmwareBytes, &receipt, nil
}
