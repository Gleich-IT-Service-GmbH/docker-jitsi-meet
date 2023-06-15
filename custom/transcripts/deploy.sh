#!/bin/sh

JITSI_WEB_FOLDER="/usr/share/jitsi-meet"
TMP_FOLDER="/tmp/deploy"

cd "$JITSI_WEB_FOLDER/transcripts"
mkdir -p "$TMP_FOLDER"
cp deploy.tar "$TMP_FOLDER/deploy.tar"

cd "$TMP_FOLDER"
tar xf deploy.tar > /dev/null
rm deploy.tar

cp -af * "$JITSI_WEB_FOLDER"

rm -rf "$TMP_FOLDER"

cd "/config"
chmod 777 "custom-config.js" "config.js"
