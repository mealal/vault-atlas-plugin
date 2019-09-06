#! /bin/bash
# Copyright 2019 Alexey Menshikov. All rights reserved.

DEP=`which dep`

if [ "$DEP" == "" ]; then
    echo "dep command not found"
    exit 1
fi

if [ -d vendor ]; then
    UPDATE="-update"
fi

$DEP ensure $UPDATE
rm -rf ./build
mkdir -p ./build
for GOOS in darwin linux; do
   for GOARCH in 386 amd64; do
     export GOOS GOARCH
     go build -o ./build/atlas-$GOOS-$GOARCH ./mongodb-atlas-plugin/main.go
   done
done