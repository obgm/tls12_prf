# tls12_prf

`prf.rb` is a simple generator script for [TLS1.2 pseudo-random
function](https://www.rfc-editor.org/rfc/rfc5246#section-5) test
vectors.

                                                                                    Usage: ./prf.rb ...
                                                                                        -k, --key=KEY                    secret key
                                                                                        -r, --generate-random=NUMBER     number of bytes for generated random seed (do not use in conjunction with -s
                                                                                        -s, --seed=SEED                  random seed
                                                                                        -l, --length=NUMBER              output length
                                                                                        -h, --hash=NAME                  Name of hash function to use. The function must be supported by OpenSSL. Default is sha256.

