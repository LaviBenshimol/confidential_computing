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

1. Generate RSA private key for Alice (3072 bits)
```bash
openssl req -new -sha384 -key alice.key -out alice.csr -passin pass:alicekey \
  -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=Alice.com" 
```

2. Sign

```bash
openssl x509 -req -in alice.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial \
  -out alice.crt -days 365 -sha384 -set_serial 02
```

## Step 3: Create Bob's Private Key and Certificate Signing Request (CSR)

1. Create Certificate Signing Request (CSR) for Bob

```bash
openssl req -new -sha384 -key bob.key -out bob.csr -passin pass:bobkey \
  -subj "/C=AU/ST=Some-State/O=CBG/CN=Boby.com"
```

2. Sign 

```bash
openssl x509 -req -in bob.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out alice.crt -days 365 -sha384 -set_serial 03 
```



#####################


udp_party -port 60000 -key alice.key -pwd alice -cert alice.crt -root rootCA.crt -peer bob
