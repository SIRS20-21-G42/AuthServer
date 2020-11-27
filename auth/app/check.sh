#!/bin/sh

MY_IP=10.74.0.5
MY_IP2=10.13.37.5

# Check if current folder exists
if [ ! -d "auth" ]; then
    mkdir auth
fi

# Check for CA certificate
if [ ! -f "CA.cert" ]; then
    echo "Getting CA certificate"
    curl --fail -k https://ca:5000/CACert > CA.cert 2> /dev/null
    if [ $? -ne 0 ]; then
        echo "Couldn't get CA certificate"
        exit 1
    fi
    echo "Trusting CA certificate"
    cat CA.cert >> /usr/local/lib/python3.7/site-packages/certifi/cacert.pem
fi

gen=false
# Check for private key
if [ ! -f "AUTH.key" ]; then
    gen=true
    echo "Generating private key"
    openssl genrsa -out AUTH.key 2> /dev/null
fi

# Check for certificate
if [ ! -f "AUTH.cert" ] || [ "$gen" = "true" ]; then
    echo "Generating CSR"
    openssl req -new -subj /O=AUTH/subjectAltName=$MY_IP,$MY_IP2,authserver_app,authserver/CN=AuthServer/ -key AUTH.key -out /tmp/csr 2> /dev/null
    echo "Getting cert"
    curl --fail --cacert CA.cert --capath . -F csr=@/tmp/csr https://ca:5000/sign > AUTH.cert 2> /dev/null
    if [ $? -ne 0 ]; then
        echo "Couldn't generate certificate"
        exit 1
    fi
fi

# Check for FaceFive certificate
while [ ! -f "FaceFive.cert" ]; do
    echo "Getting FaceFive certificate"
    curl --fail --cacert CA.cert --capath . https://ca:5000/cert/FaceFive > FaceFive.cert
    if [ $? -ne 0 ]; then
        echo "Waiting for FaceFive cert to be available"
        rm FaceFive.cert
        sleep 5
    fi
done
