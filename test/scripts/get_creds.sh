#! /bin/sh
# Copyright 2019 Alexey Menshikov. All rights reserved.

export VAULT_ADDR=http://127.0.0.1:8200
export ROOT_TOKEN=$(cat /vault.init | grep '^Initial' | awk '{print $4}')
vault login $ROOT_TOKEN > /dev/null
vault read database/creds/readonly