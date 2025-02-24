#!/usr/bin/env bash

export LC_ALL=C

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"/../.. || exit

DOCKER_IMAGE=${DOCKER_IMAGE:-sccpay/sccd-develop}
DOCKER_TAG=${DOCKER_TAG:-latest}
DOCKER_RELATIVE_PATH=contrib/containers/deploy

BUILD_DIR=${BUILD_DIR:-.}


if [ -d $DOCKER_RELATIVE_PATH/bin ]; then
    rm $DOCKER_RELATIVE_PATH/bin/*
fi

mkdir $DOCKER_RELATIVE_PATH/bin
cp "$BUILD_DIR"/src/sccd    $DOCKER_RELATIVE_PATH/bin/
cp "$BUILD_DIR"/src/scc-cli $DOCKER_RELATIVE_PATH/bin/
cp "$BUILD_DIR"/src/scc-tx  $DOCKER_RELATIVE_PATH/bin/
strip $DOCKER_RELATIVE_PATH/bin/sccd
strip $DOCKER_RELATIVE_PATH/bin/scc-cli
strip $DOCKER_RELATIVE_PATH/bin/scc-tx

docker build --pull -t "$DOCKER_IMAGE":"$DOCKER_TAG" -f $DOCKER_RELATIVE_PATH/Dockerfile docker
