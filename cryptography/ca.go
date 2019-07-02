package cryptography

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	mathrand "math/rand"
	"time"
)

type Cert struct {
	IsCA               bool
	Country            string
	Organization       string
	OrganizationalUnit string
	Locality           string
	Province           string
	StreetAddress      string
	PostalCode         string
	CommonName         string
	ExpiryDate         string
}

func (cert *Cert) generateTemplate(privateKey *rsa.PrivateKey) (certificateTemplate *x509.Certificate) {
	mathrand.Seed(time.Now().UnixNano())
	randomInteger := mathrand.Intn(math.MaxInt64)
	randomInteger64 := int64(randomInteger)
	subjectKeyID := HashBigInt(privateKey.N)
	template := &x509.Certificate{
		IsCA:         cert.IsCA,
		SubjectKeyId: subjectKeyID,
		SerialNumber: big.NewInt(randomInteger64),
		Subject: pkix.Name{
			Country:            []string{cert.Country},
			Organization:       []string{cert.Organization},
			OrganizationalUnit: []string{cert.OrganizationalUnit},
			Locality:           []string{cert.Locality},
			Province:           []string{cert.Province},
			StreetAddress:      []string{cert.StreetAddress},
			PostalCode:         []string{cert.PostalCode},
			CommonName:         cert.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 5, 5),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return template
}

func (cert *Cert) GenerateCA() (privatekey *rsa.PrivateKey, publickey *rsa.PublicKey, certificate []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
	}

	publicKey := &privateKey.PublicKey
	caTemplate := cert.generateTemplate(privatekey)
	caCert, err := cert.generateCert(caTemplate, caTemplate, privateKey, publicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, publicKey, caCert, nil
}

func (cert *Cert) GenerateClientCertificate(caTemplate *x509.Certificate, parentTemplate *x509.Certificate, caPrivateKey *rsa.PrivateKey) (privatekey *rsa.PrivateKey, publickey *rsa.PublicKey, certificate []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
	}

	publicKey := &privateKey.PublicKey
	clientCert, err := cert.generateCert(caTemplate, parentTemplate, caPrivateKey, publicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, publicKey, clientCert, nil
}

func (cert *Cert) generateCert(caTemplate *x509.Certificate, parentTemplate *x509.Certificate, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) (certificate []byte, err error) {
	certBody, err := x509.CreateCertificate(rand.Reader, caTemplate, parentTemplate, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return certBody, nil
}

func VerifyCertificate(rootPEM []byte, certPEM []byte) error {
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	ok := roots.AppendCertsFromPEM(rootPEM)
	if !ok {
		return errors.New("Failed to parse root certificate")
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("Failed to parse certificate PEM ")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return errors.New("Failed to parse certificate with error: " + err.Error())
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
	}
	_, err = cert.Verify(opts)
	if err != nil {
		return errors.New("Failed to verify certificate with error: " + err.Error())
	}

	return nil
}

func HashBigInt(bigInt *big.Int) []byte {
	hash := sha1.New()
	hash.Write(bigInt.Bytes())
	return hash.Sum(nil)
}
