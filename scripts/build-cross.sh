#!/bin/bash

DIRECTORY=./libs
if [[ -d "$DIRECTORY" ]]
then
    echo "$DIRECTORY exists on your filesystem. Delete it and run the script again."
    exit 0
fi

export RUSTFLAGS="-Ccodegen-units=1"
export CROSS_CONFIG="$PWD/scripts/Cross.toml"

rustup default stable

cargo install cross --git https://github.com/cross-rs/cross --branch main
cargo install cargo-lipo
# cargo install cargo-strip

pushd lib/rln

cargo clean

cross build --release --lib --target=aarch64-linux-android
cross build --release --lib --target=armv7-linux-androideabi
cross build --release --lib --target=i686-linux-android
cross build --release --lib --target=x86_64-linux-android
cross build --release --lib --target=x86_64-unknown-linux-musl

# These depend on https://github.com/cross-rs/cross/pull/591 being merged
# In the meantime, we can follow the instructions from here
# https://github.com/cross-rs/cross/wiki/FAQ#newer-linux-versions
# to build the docker images locally. Once that PR is merged,
# remove the CROSS_CONFIG variable and Cross.toml file

cross build --release --lib --target=x86_64-pc-windows-gnu
cross build --release --lib --target=aarch64-unknown-linux-gnu
cross build --release --lib --target=x86_64-unknown-linux-gnu
cross build --release --lib --target=arm-unknown-linux-gnueabi
cross build --release --lib --target=i686-pc-windows-gnu
cross build --release --lib --target=i686-unknown-linux-gnu
cross build --release --lib --target=arm-unknown-linux-gnueabihf
cross build --release --lib --target=mips-unknown-linux-gnu
cross build --release --lib --target=mips64-unknown-linux-gnuabi64
cross build --release --lib --target=mips64el-unknown-linux-gnuabi64
cross build --release --lib --target=mipsel-unknown-linux-gnu

# TODO: these work only on iOS
rustup target add aarch64-apple-ios x86_64-apple-ios
cross build --release --target=x86_64-apple-darwin --lib
cross build --release --target=aarch64-apple-darwin --lib
cargo lipo --release --targets=aarch64-apple-ios,x86_64-apple-ios

popd

TOOLS_DIR=`dirname $0`
COMPILE_DIR=${TOOLS_DIR}/../lib/rln/target
rm -rf $COMPILE_DIR/x86_64-apple-ios $COMPILE_DIR/aarch64-apple-ios
for platform in `ls ${COMPILE_DIR} | grep -v release | grep -v debug`
do
  PLATFORM_DIR=${DIRECTORY}/$platform
  mkdir -p ${PLATFORM_DIR}
  cp ${COMPILE_DIR}/$platform/release/librln.{a,lib} ${PLATFORM_DIR}
done
