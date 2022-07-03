# go-rln

Wrappers for [kilic/rln](https://github.com/kilic/rln) along with an implementation for rate-limiting using RLN inspired
by the [Waku v2 RLN Relay](https://rfc.vac.dev/spec/17/) built by [Status](https://status.im).

Further research can be found here:
 - https://forum.vac.dev/t/vac-3-zk/97
 - https://github.com/vacp2p/research/tree/master/rln-research
 - https://ethresear.ch/t/semaphore-rln-rate-limiting-nullifier-for-spam-prevention-in-anonymous-p2p-setting/5009

The goal of this is to create a rate-limiter for blockchains where block production is cheap. I started playing around with this
after talking to the team at [Celestia](https://celestia.org/).


### Building this library

#### Using [cross](https://github.com/cross-rs)

```
make rlnlibs-cross
```

Some architectures are not available in cross unless they're locally build. This [PR](https://github.com/cross-rs/cross/pull/591) will update ubuntu base version on cross. But while it's merged, build them locally. To build them locally execute the following instructions (adapted from [here](https://github.com/cross-rs/cross/wiki/FAQ#newer-linux-versions)):

```
git clone --single-branch --depth 1 --branch increment_versions https://github.com/Alexhuszagh/cross
cd cross
cargo build-docker-image x86_64-pc-windows-gnu
cargo build-docker-image aarch64-unknown-linux-gnu
cargo build-docker-image x86_64-unknown-linux-gnu
cargo build-docker-image arm-unknown-linux-gnueabi
cargo build-docker-image i686-pc-windows-gnu
cargo build-docker-image i686-unknown-linux-gnu
cargo build-docker-image arm-unknown-linux-gnueabihf
cargo build-docker-image mips-unknown-linux-gnu
cargo build-docker-image mips64-unknown-linux-gnuabi64
cargo build-docker-image mips64el-unknown-linux-gnuabi64
cargo build-docker-image mipsel-unknown-linux-gnu
```

#### Using [rustup](https://rust-lang.github.io/rustup/cross-compilation.html)

```
make rlnlibs-cross
```