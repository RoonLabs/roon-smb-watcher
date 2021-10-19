#!/bin/bash

set -ex

function gitclone {
    if [ ! -d $2 ]; then
        rm -rf tmp
        mkdir tmp
        pushd tmp > /dev/null
        SL GITCLONE-$2: cloning $1
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

rm -rf libsmb2
rm -rf libdsm

gitclone https://github.com/sahlberg/libsmb2.git libsmb2 4a5a0d0c9498c8a2a6b7d21cc3454229c81ae5c0
#gitclone https://github.com/RoonLabs/libdsm.git 4a5a0d0c9498c8a2a6b7d21cc3454229c81ae5c0
gitclone ben@192.168.1.135:/home/ben/bcoburn3-github/libdsm 

echo "Building libsmb2"
echo ================================================================================

pushd libsmb2
./bootstrap
./configure --disable-werror --without-libkrb5
make -j8
