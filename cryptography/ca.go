package cryptography

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

const CERTUSAGES = x509.KeyUsageDigitalSignature

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

func (cert *Cert) GenerateTemplate() (certificateTemplate *x509.Certificate) {
	template := &x509.Certificate{
		IsCA:         cert.IsCA,
		SubjectKeyId: []byte{1, 2, 3, 7},
		SerialNumber: big.NewInt(1234),
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

func GenerateCA(caTemplate *x509.Certificate) (privatekey *rsa.PrivateKey, publickey *rsa.PublicKey, certificate []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
	}

	publicKey := &privateKey.PublicKey
	cert, err := createCert(caTemplate, caTemplate, privateKey, publicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, publicKey, cert, nil
}

func GenerateCertificate(caTemplate *x509.Certificate, parentTemplate *x509.Certificate, caPrivateKey *rsa.PrivateKey) (privatekey *rsa.PrivateKey, publickey *rsa.PublicKey, certificate []byte, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
	}

	publicKey := &privateKey.PublicKey
	cert, err := createCert(caTemplate, parentTemplate, caPrivateKey, publicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, publicKey, cert, nil
}

func createCert(caTemplate *x509.Certificate, parentTemplate *x509.Certificate, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) (certificate []byte, err error) {
	cert, err := x509.CreateCertificate(rand.Reader, caTemplate, parentTemplate, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	return cert, nil
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
	fmt.Println(cert.Issuer)
	_, err = cert.Verify(opts)
	if err != nil {
		return errors.New("Failed to verify certificate with error: " + err.Error())
	}

	return nil
}
