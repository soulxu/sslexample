cfssl gencert \
  -ca=ca.pem \
  -ca-key=ca-key.pem \
  -config=ca-config.json \
  -hostname=127.0.0.1,newnuc,192.168.0.100 \
  -profile=sslexample \
  server-csr.json | cfssljson -bare sslserver
