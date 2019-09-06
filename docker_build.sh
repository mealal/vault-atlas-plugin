#! /bin/bash
# Copyright 2019 Alexey Menshikov. All rights reserved.

rm -rf ./build
docker build -t plugin-builder .
docker run --rm -d --name plugin-builder plugin-builder tail -f /dev/null
docker cp plugin-builder:/app ./build
docker stop plugin-builder -t 0
docker rmi plugin-builder -f
