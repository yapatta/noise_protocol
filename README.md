# Noise Protocol Framework

This package implements Noise Protool Framework as a playground.

## NOTE

Current version neither validates handshake patterns enough nor provides all handshake patterns specified in the [specification](https://noiseprotocol.org/noise.html), so it would not be recommend to use this library in practice for now.

It is better to use existing libraries like [nyquist](https://github.com/Yawning/nyquist).

## Supported Patterns

- one-way pattern: N
- interactive pattern: NN, XX, KN, IX, XKpsk3
- deffered pattern: NK1

## TODOs

- validate handshakes
- support more handshake patterns
- support more DH algorithms
- support more hash algorithms
- support more AEAD encryptions
