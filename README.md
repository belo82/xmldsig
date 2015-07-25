# xmldsig

Library to make working with XMLDsig Java API easier

## Generating private keys and certificates

To be able to sign request and response, we need to:

* setup demo certification authority (CA)
* create self signed CA's certificate
* generate client's key pair we will be signing requests with and issue certificate for it using our demo CA
* generate server's key pair we will be signing responses with and issue certificate for it using our demo CA

### Certification Authority setup

Before we start, we need to create demo Certification Authority (CA). 

To do that, first change content of the `openssl.cnf` file which is by default located in `/usr/local/etc/openssl/`

    [ usr_cert ]
    basicConstraints=CA:TRUE # prev value was FALSE
    
To setup new CA directory structure and generate CA's self signed certificate run:

    /usr/local/etc/openssl/misc/CA.sh -newca
        
### Optional: Generating CA's key pair and self signed certificate manually

This was done for you by `CA.sh` script so usually you don't need to run this manually 

    openssl req -newkey rsa:2048 -nodes -keyout ca.key -x509 -days 365 -out ca.crt
    openssl x509 -in ca.crt -text -noout # check content of the certificate
    
### Generating client's key pair and CSR

We need to generate key and Certificate Signing Request (CSR)

You can do it manually:

    # generate client's key and CSR
    openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr
    
    # check content of the CSR
    openssl req -text -noout -verify -in client.csr
    
Or using `CA.sh` script:

    ./CA.sh -newreq
    
### Generating server key pair and CSR

Same steps as for the client's key and CSR

    openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr
    # or again using CA.sh -newreq script
    
### Sign CSRs with CA's key

Last thing we need to do is sign created CSRs with CA's key and generate certificates

    openssl ca -policy policy_anything -keyfile ca.key -cert ca.crt -out client.crt -infiles client.csr
    openssl ca -policy policy_anything -keyfile ca.key -cert ca.crt -out server.crt -infiles server.csr
    
    # or using CA.sh script
    
    CA.sh -sign 
    
    # if you want to check content of the generated certificate
    openssl x509 -in client.crt -text -noout
    
### Converting key to PKCS format

    openssl pkcs8 -topk8 -inform PEM -outform DER -in client-key.pem -nocrypt > client-key.pkcs
    
## Usage

todo

## Testing

todo

## Issues

todo

## License

todo
    
