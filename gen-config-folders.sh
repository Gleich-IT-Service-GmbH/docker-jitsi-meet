#!/usr/bin/env bash

CONFIG_FOLDER=$(cat .env | grep CONFIG | cut -d "=" -f2-)
mkdir -p "$CONFIG_FOLDER/"{web/crontabs,web/letsencrypt,transcripts,prosody/config,prosody/prosody-plugins-custom,jicofo,jvb,jigasi,jibri,postgres}

# TODO: Add wget request for customization tar/zip file.
# TODO: Extract files

if [[ ! -f .env ]]; then
    cp env.example .env
fi

cp -af "./custom/"* "$CONFIG_FOLDER/"

# Set docker-compose variables
sed -i.bak \
    -e "s#\${CONFIG}#${CONFIG_FOLDER}#g" \
    "$(dirname "$0")/docker-compose.yml"
