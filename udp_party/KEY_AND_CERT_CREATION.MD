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

1. Generate RSA private key for Bob (3072 bits)
```bash
openssl genrsa -out alice.key 3072 
```

```bash
openssl req -new -key alice.key -out alice.csr -sha384 
```

3. Remove the unencrypted key
```bash
rm bob_unencrypted.key
```

4. Create Certificate Signing Request (CSR) for Bob
```bash
openssl req -new -sha384 -key bob.key -out bob.csr -passin pass:bobkey \
  -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=Bob.com"
```
  
## Step 3:


#####################


udp_party -port 60000 -key alice.key -pwd alice -cert alice.crt -root rootCA.crt -peer bob
