# go-rln

Wrappers for [kilic/rln](https://github.com/kilic/rln) along with an implementation for rate-limiting using RLN inspired
by the [Waku v2 RLN Relay](https://rfc.vac.dev/spec/17/) built by [Status](https://status.im).

Further research can be found here:
 - https://forum.vac.dev/t/vac-3-zk/97
 - https://github.com/vacp2p/research/tree/master/rln-research
 - https://ethresear.ch/t/semaphore-rln-rate-limiting-nullifier-for-spam-prevention-in-anonymous-p2p-setting/5009

The goal of this is to create a rate-limiter for blockchains where block production is cheap. I started playing around with this
after talking to the team at [Celestia](https://celestia.org/).


###
The following architectures require newer versions of glibc. 

- `x86_64-pc-windows-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`
- `arm-unknown-linux-gnueabi`

This [PR](https://github.com/cross-rs/cross/pull/591) will update ubuntu base version on cross. But while it's merged, follow the instructions from [here](https://github.com/cross-rs/cross/wiki/FAQ#newer-linux-versions) to locally build docker images for those architectures.