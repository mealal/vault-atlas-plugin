#! /bin/bash
# Copyright 2019 Alexey Menshikov. All rights reserved.

DEP=`which dep`

if [ "$DEP" == "" ]; then
    echo "dep command not found"
    exit
fi

if [ -d vendor ]; then
    UPDATE="-update"
fi

$DEP ensure $UPDATE
go build -o atlas ./mongodb-atlas-plugin/main.go