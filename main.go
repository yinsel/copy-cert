package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net/url"
	"os"
	"slices"
	"strings"
	"net"
)

type certPair struct {
	originCert *x509.Certificate
	newCert    *x509.Certificate
	newCertPem []byte
	priv       interface{}
	privPem    []byte
}

func getCertsFromNetwork(addr string) ([]*x509.Certificate, error) {
	conf := &tls.Config{
		InsecureSkipVerify: false,
	}
	conn, err := tls.Dial("tcp", addr, conf)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}

func makeCerts(originCerts []*x509.Certificate, ipSAN string) ([]*certPair, error) {
	certs := make([]*certPair, len(originCerts))
	for idx, cert := range originCerts {
		log.Printf("got cert: %s", cert.Subject.CommonName)
		certs[idx] = &certPair{originCert: cert}
	}
	slices.Reverse(certs)

	for idx, pair := range certs {
		var pub interface{}
		switch pair.originCert.PublicKey.(type) {
		case *rsa.PublicKey:
			p, err := rsa.GenerateKey(rand.Reader, pair.originCert.PublicKey.(*rsa.PublicKey).Size()*8)
			if err != nil {
				return nil, fmt.Errorf("generate rsa key: %w", err)
			}
			pub = &p.PublicKey
			pair.priv = p
			pair.privPem = pem.EncodeToMemory(&pem.Block{Bytes: x509.MarshalPKCS1PrivateKey(p), Type: "RSA PRIVATE KEY"})
		case *ecdsa.PublicKey:
			p, err := ecdsa.GenerateKey(pair.originCert.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
			if err != nil {
				return nil, fmt.Errorf("generate ec key: %w", err)
			}
			pub = &p.PublicKey
			pair.priv = p
			data, err := x509.MarshalPKCS8PrivateKey(p)
			if err != nil {
				return nil, fmt.Errorf("MarshalPKCS8PrivateKey: %w", err)
			}
			pair.privPem = pem.EncodeToMemory(&pem.Block{Bytes: data, Type: "EC PRIVATE KEY"})
		default:
			return nil, fmt.Errorf("unknown key type: %T", pair.originCert.PublicKey)
		}

		pair.originCert.PublicKey = nil
		pair.originCert.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
		
		if ipSAN != "" {
			ip := net.ParseIP(ipSAN)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP address: %s", ipSAN)
			}
			pair.originCert.IPAddresses = append(pair.originCert.IPAddresses, ip)
		}

		pair.newCert = pair.originCert

		var parent *certPair

		if idx > 0 {
			parent = certs[idx-1]
		} else {
			parent = pair
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, pair.originCert, parent.newCert, pub, parent.priv)
		if err != nil {
			return nil, fmt.Errorf("CreateCertificate: %w", err)
		}
		pair.newCertPem = pem.EncodeToMemory(&pem.Block{Bytes: derBytes, Type: "CERTIFICATE"})
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			return nil, fmt.Errorf("ParseCertificate: %w", err)
		}
		pair.newCert = cert
	}
	return certs, nil
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		log.Fatalf("usage: %s https://example.com/ [optional IP SAN]", os.Args[0])
	}

	ipSAN := ""
	if len(os.Args) == 3 {
		ipSAN = os.Args[2]
	}

	// 解析 URL
	u, err := url.Parse(os.Args[1])
	if err != nil {
		log.Fatalf("invalid URL: %v", err)
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":443"
	}

	certs, err := getCertsFromNetwork(host)
	if err != nil {
		log.Fatal(err)
	}
	newCerts, err := makeCerts(certs, ipSAN)
	if err != nil {
		log.Fatal(err)
	}
	slices.Reverse(newCerts)

	// 写入 server.crt (bundle)
	crtFile, err := os.OpenFile("server.crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	defer crtFile.Close()

	keyFile, err := os.OpenFile("server.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer keyFile.Close()

	for _, pair := range newCerts {
		_, err = crtFile.Write(pair.newCertPem)
		if err != nil {
			log.Fatal(err)
		}
	}

	_, err = keyFile.Write(newCerts[0].privPem)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Generated server.crt (bundle) and server.key in current directory.")
}
