# ha1x

A tool for generating Digest Authentication final or intermediary values.

## Overview

Digest authentication is used to provide a secure way of authenticating users for
protocols such as SIP (VoIP) or HTTP (e.g., for API requests). More details about:

- https://en.wikipedia.org/wiki/Digest_access_authentication

The `ha1x` tool is capable of MD5, SHA-1, SHA-256, SHA-384 and SHA-512 hashing.
It can compute the values for HA1 (or HA1B), HA2 and the Digest response. For
convenience, it can also compute the hash of a single input value.

## Usage

Run `ha1x -h` for help on the command line options.

Generating HA1 value:

```
ha1x <username> <realm> <password>
```

For example:

```
# ha1x alice kamailio.org secret
Hash: bd41b545ba2d8498ae89bc75e3e0b87e
```

Generating HA2 value:

```
ha1x -2 <method> <uri>
```

For example:

```
ha1x -2 INVITE sip:alice@kamailio.org
Hash: 99fb5d7b87061c7898dc1011fc58a8b3
```

Generating the Digest response:

```
ha1x -r <username> <realm> <method> <uri> <nonce> <password>
```

## License

GPLv3
