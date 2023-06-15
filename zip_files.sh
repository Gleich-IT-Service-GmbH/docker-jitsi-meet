#/bin/bash

VERSION="0_0_1"

###############################################

rm jitsi_modified.tar "release_$VERSION.zip"

./build.sh release

echo "Zipping files together..."

zip -r "release_$VERSION.zip" \
    custom \
    docker-compose.yml \
    env.example \
    gen-config-folders.sh \
    gen-passwords.sh \
    jitsi_modified.tar \
    etherpad.yml \
    jibri.yml \
    jigasi.yml \
    LICENSE

echo "Finished zipping"

###############################################
