cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -profile=sslexample \
  client-csr.json | cfssljson -bare client
