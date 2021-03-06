#!/bin/bash

set -ex

function gitclone {
    if [ ! -d $2 ]; then
        rm -rf tmp
        mkdir tmp
        pushd tmp > /dev/null
        git clone --no-checkout $1 $2
        pushd $2 > /dev/null
        git checkout $3
        popd > /dev/null
        mv * ..
        popd > /dev/null
        rm -rf tmp
    elif [ ! -z $3 ]; then
        pushd $2 > /dev/null
        git checkout $3
        popd > /dev/null
    fi
}

ROOT=$PWD

if [ ! -d subprojects ]; then mkdir subprojects; fi
pushd subprojects/
rm -rf libsmb2
rm -rf libdsm

if [ "x`uname -o`" != "xCygwin" ]; then
    gitclone https://github.com/sahlberg/libsmb2.git libsmb2 4a5a0d0c9498c8a2a6b7d21cc3454229c81ae5c0
fi
gitclone https://github.com/RoonLabs/libdsm.git libdsm 

if [ "x`uname -o`" != "xCygwin" ]; then
echo "Building libsmb2"
echo ================================================================================
pushd libsmb2
    ./bootstrap
    ./configure --disable-werror --without-libkrb5 --prefix=$ROOT/tmp
    make -j8
    make install
    cp $ROOT/tmp/lib/libsmb2.a libsmb2.a
popd
cp $ROOT/libsmb2binary.meson.build $ROOT/subprojects/libsmb2/meson.build
fi

cd $ROOT


echo "Building roon-smb-watcher"
echo ================================================================================
WIPE_ARG=""
if [ -d build ]; then WIPE_ARG="--wipe"; fi
meson setup "$@" $WIPE_ARG build
pushd build
ninja
popd
