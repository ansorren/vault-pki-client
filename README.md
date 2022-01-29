# vault-pki-client
A tiny wrapper around the HashiCorp Vault PKI secrets engine.
This client allows you to enable the PKI secrets engine, generate the certs,
have the root sign the intermediate and re-import the signed certificate.
This client follows the steps outlined in the official HashiCorp tutorial [here](https://learn.hashicorp.com/tutorials/vault/pki-engine)
with the exception of the creation of the PKI role and the issue of the leaf certificates,
which will be implemented in the future.

## Usage 
To test the behavior of the client, you can run the docker compose file contained with this 
repo, which will spin up two Vault containers running on ports 8200
and 8201:

```
docker-compose up -d
```

Now you can generate the root and the intermediate CA and perform
the signing procedure as follows:

```golang
package main

import (
	"fmt"
	"net/http"

	"github.com/ansorren/vault-pki-client"
)

func main() {
	// instantiate the client for the root CA vault cluster
	rootClient, err := pki.NewClient(
		pki.WithAddress("http://localhost:8200"),
		pki.WithToken("admin"),
	)
	if err != nil {
		panic(err)
	}

	// instantiate the client for the intermediate CA vault cluster
	intermediateClient, err := pki.NewClient(
		pki.WithAddress("http://localhost:8201"),
		pki.WithToken("admin"),
	)
	if err != nil {
		panic(err)
	}

	// Enable the root CA PKI secrets engine
	err = rootClient.EnablePKIEngine("pki")
	if err != nil {
		panic(err)
	}

	// Enable the intermediate CA PKI secrets engine
	err = intermediateClient.EnablePKIEngine("pki")
	if err != nil {
		panic(err)
	}


	// Generate the root CA certificate
	rootCaCert, err := rootClient.GenerateRootCA("pki", "root.localhost")
	if err != nil {
		panic(err)
	}
	fmt.Println("common name of the root CA certificate:", rootCaCert.Subject.CommonName)

	// Generate the intermediate CA certificate
	csr, err := intermediateClient.GenerateIntermediateCA("pki", "intermediate.localhost")
	if err != nil {
		panic(err)
	}

	// Ask the root CA to sign the intermediate
	signedCertificate, err := rootClient.SignIntermediateCA("pki", csr)
	if err != nil {
		panic(err)
	}

	// Import the certificate signed by the root CA back into the intermediate
	// PKI secrets engine
	err = intermediateClient.SetSignedCertificate("pki", signedCertificate)
	if err != nil {
		panic(err)
	}
}
```
Now query the unauthenticated Vault endpoint listed [here](https://www.vaultproject.io/api-docs/secret/pki#read-ca-certificate)
with the following command, and you should see that the intermediate certificate (intermediate.localhost) has been signed by 
root.localhost (the `Issuer` field):

```
curl http://localhost:8201/v1/pki/ca/pem | openssl x509 -noout -text


Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            02:fd:22:b8:7a:d4:33:6e:6a:35:43:35:f7:0b:75:79:ea:5a:31:75
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=root.localhost
        Validity
            Not Before: Jan 28 17:01:38 2022 GMT
            Not After : Jan 26 17:02:08 2032 GMT
        Subject: CN=intermediate.localhost
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ca:d6:8b:41:98:89:3e:86:d0:7d:1e:eb:91:2f:
                    28:c5:0b:30:96:b8:9f:20:d0:b2:99:33:48:51:22:
                    34:12:22:85:2f:ca:46:9f:16:75:12:52:48:b6:99:
                    2e:8a:c3:aa:f7:d6:56:8a:21:ee:96:cd:41:3b:94:
                    79:2e:99:ef:e1:06:bf:c1:29:15:5c:87:37:8e:ec:
                    b5:5f:c3:d1:fb:55:49:97:6f:a1:4a:12:0d:d6:f7:
                    dd:1f:78:2a:90:bf:69:9b:c7:27:b9:0a:3b:82:8b:
                    3c:08:92:0b:44:90:a8:d4:62:12:09:38:3a:1f:31:
                    2c:38:f3:48:0f:2a:74:0a:e0:dd:dd:52:c2:52:2c:
                    29:a9:54:3e:04:ea:23:ae:01:3a:ff:bd:19:b1:33:
                    02:ed:ce:36:6f:6b:ee:e3:c4:8f:40:c2:40:33:ca:
                    37:22:d3:42:60:ad:24:ce:10:82:07:97:c9:6c:5d:
                    48:f4:c7:f9:b7:02:6e:40:9f:ca:0f:bc:57:6a:65:
                    a3:e0:38:76:32:9f:25:cd:85:c7:16:3a:93:55:8b:
                    b3:d7:8f:ca:8f:ad:35:b1:6e:b1:77:45:05:11:19:
                    fc:88:b2:a8:28:af:e6:f9:0f:0c:c3:03:d6:07:fd:
                    98:30:46:2f:a6:6b:21:df:70:f3:ad:8f:37:72:dc:
                    f8:c7
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                81:7B:1A:87:CC:4E:DB:BF:BC:2C:5C:06:19:2C:18:A6:46:EA:D6:D8
            X509v3 Authority Key Identifier: 
                keyid:D2:A9:99:42:58:A4:DE:75:40:8E:99:46:29:39:05:C9:38:77:98:22

            X509v3 Subject Alternative Name: 
                DNS:intermediate.localhost
    Signature Algorithm: sha256WithRSAEncryption
         96:f3:29:0e:a0:24:c0:e2:ae:f0:1d:b1:8c:7c:8c:b0:05:1b:
         72:fa:2c:6b:e1:88:bc:20:87:da:66:7a:0a:cc:7c:cf:6e:88:
         85:f9:1f:91:94:d0:3b:01:3e:60:15:82:c9:c3:8c:64:c2:26:
         d2:4a:30:b1:b7:b5:e0:b7:79:9e:62:d2:ce:93:f0:c2:bc:e9:
         49:7a:a1:67:4c:ff:fb:2d:78:46:73:78:4f:3b:4c:f5:03:df:
         3b:9a:f0:7b:fb:9a:04:d8:9a:cf:9c:2c:c3:7c:26:cd:b5:0e:
         1d:3e:1c:cc:6c:76:65:cb:19:22:15:27:a8:7c:58:4d:32:60:
         84:24:cc:b5:64:5d:b9:97:12:61:04:e4:d8:af:e6:9d:9e:94:
         b9:9e:d7:c6:d7:eb:72:ae:85:5a:3e:9a:80:b7:13:52:2d:94:
         b9:b6:55:77:e9:a0:71:2d:10:f1:f1:f5:da:86:be:62:57:19:
         d3:84:50:38:04:3a:c0:ef:3d:d9:4f:41:47:fe:e1:3b:06:e5:
         94:62:ec:61:16:a6:8c:ca:a0:f7:1c:a4:e8:45:da:ff:ca:39:
         23:ee:ed:03:15:b3:40:82:8d:e7:95:7e:63:32:1f:38:32:7d:
         a6:e5:bd:0c:39:e6:d3:44:b4:9d:b4:17:92:f5:75:dd:fa:64:
         7a:2b:2e:2c
```
