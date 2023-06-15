#!/bin/bash

docker-compose down;

make;

if [[ $? != 0 ]]; then
    echo "Failed to build see build process log";
    exit 1;
fi

MODULES=("prosody" "web" "postgres")

for module in "${MODULES[@]}"; do
    echo "Retagging latest to modified for: $module";
    docker image tag "jitsi/$module:latest" "jitsi/$module:modified";
done

if [[ "$1" == "release" ]]; then
    echo "Creating build tar file...";

    IMAGES="";
    for module in "${MODULES[@]}"; do
        IMAGES="$IMAGES jitsi/$module:modified";
    done

    docker save --output jitsi_modified.tar $IMAGES;

    echo "Finished creating release build"
else
    echo "Finished creating build...restarting container"

    docker-compose up -d;
fi
