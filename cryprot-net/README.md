# SEEC-Channel

An improved asynchronous Channel for SEEC based on QUIC and 0-RTT sub-streams.

## TODO

- (optionally?) track number of bytes read and written for each sub-stream
    - provide API to track communication as belonging to a (potentially nested) phase
    - open question: this would track communication at the level of a QUIC stream and thus not include QUIC overhead. I
      think there might be a way to get the complete communication amount via events, to at least report this overhead
- Multi-Channel
- Optional insecure communication? Currently, TLS is always used, but maybe a user wishes to not use it
    - I think there is some testing code in s2n-quick for
      this [here](https://github.com/aws/s2n-quic/blob/d03cc470fa9812d06d204e312e4ada00079e96df/quic/s2n-quic-core/src/crypto/tls/null.rs#L440)
      only available with testing feature