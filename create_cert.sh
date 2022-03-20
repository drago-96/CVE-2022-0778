#!/bin/bash

# find your curve
#openssl ecparam -list_curves

# create privatekey
#openssl ecparam -out ec.key -name prime256v1 -genkey -noout

# create privatekey contains explicit elliptic curve parameters
# with a base point encoded in compressed form
openssl ecparam -out ec.key -name prime256v1 -genkey -noout -param_enc explicit -conv_form compressed

# show the privatekey info 
# openssl ec -in ec.key -text -noout

# create a self-signed certificate
openssl req -new -x509 -key ec.key -out cert.der -outform DER -days 360 -subj "/CN=TEST/"

# show the cert info
# openssl x509 -in cert.der -text -noout -inform DER
