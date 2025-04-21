# Key and Certifications Creation

The key creation required for this application is as follows:

- Alice
- Bob
- RootCA


## Step 1: Create the root CA

1. Generate a new RSA private key for the root CA (3072 bits as per the exercise requirements)

```bash
openssl genrsa -out rootCA.key 3072
```

2. Create a self-signed root certificate with SHA384 and serial 01

```bash
openssl req -x509 -new -sha384 -nodes -key rootCA.key -days 1024 -out rootCA.crt -set_serial 01 \
  -subj "/C=AU/ST=US/O=CBG/CN=rootCA"
```

## Step 2: Create Alice's Private Key and Certificate Signing Request (CSR)

- Generate RSA private key for Alice (3072 bits)
```bash
openssl genrsa -out alice_unencrypted.key 3072
```
- Encrypt with the password alice:

```bash
openssl rsa -in alice_unencrypted.key -out alice.key -aes256 -passout pass:alice
```

- Create Alice's CSR
```bash
openssl req -new -sha384 -key alice.key -out alice.csr -passin pass:alice \
  -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=Alice.com"
```

- Sign
```bash
 openssl x509 -req -in alice.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out alice.crt -days 365 -sha384 -set_serial 02
```


## Step 3: Create Bob's Private Key and Certificate Signing Request (CSR)

- Create private key

```bash
openssl genrsa -out bob_unencrypted.key 3072
```

- Encrypt Bob's key with password "bobkey"


```bash
openssl rsa -in bob_unencrypted.key -out bob.key -aes256 -passout pass:bobkey
```

- Create Bob's CSR with the correct CN of "Bob.com"
```bash
openssl req -new -sha384 -key bob.key -out bob.csr -passin pass:bobkey \
-subj "/C=AU/ST=Some-State/O=CBG/CN=Bob.com"
```

- Sign

```bash
openssl x509 -req -in bob.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out bob.crt -days 365 -sha384 -set_serial 03
```