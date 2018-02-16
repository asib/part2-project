An explanation about all the files with "ecdsa" in their name:

 - "ecdsa" is the PKCS8-encoded private key. Thus it contains not just the secret
 value d, but also information about the curve.
 - "ecdsa_pub" is the X509-encoded public key. Again, it contains not just the
 public point Q, but also information about the curve.
 - "ecdsa_pub_point" contains the uncompressed encoding of the point Q, AND NOTHING
 MORE. This file exists only for the purpose of generating a signature.
 - "ecdsa_sig" contains the ECDSA signature of the uncompressed encoding of the
 public point.
