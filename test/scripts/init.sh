#! /bin/sh
# Copyright 2019 Alexey Menshikov. All rights reserved.

function usage() {

    echo "usage: start.sh --apiID=your_api_id --apiKey=your_api_key --groupID=your_group_id"
    exit 2
}

if [ $# -eq 0 ]; then
    usage
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --help)
            usage
            ;;
        --apiID=*)
            api_id="${1#*=}"
            shift
            ;;
        --apiKey=*)
            api_key="${1#*=}"
            shift
            ;;
        --groupID=*)
            group_id="${1#*=}"
            shift
            ;;
            *)
            printf "Invalid argument: %s\n" ${1}
            exit 1
            ;;
    esac
done

if [ "$api_id" == "" ]; then
  echo "apiID must not be empty"
  exit 2
fi

if [ "$api_key" == "" ]; then
  echo "apiKey must not be empty"
  exit 2
fi

if [ "$group_id" == "" ]; then
  echo "groupID must not be empty"
  exit 2
fi
export VAULT_ADDR=http://127.0.0.1:8200
vault operator init | tee /vault.init > /dev/null
cat /vault.init | grep '^Unseal' | awk '{print $4}' | for key in $(cat -); do
  vault operator unseal $key
done
export ROOT_TOKEN=$(cat /vault.init | grep '^Initial' | awk '{print $4}')
vault login $ROOT_TOKEN
setcap cap_ipc_lock=+ep /vault/file/atlas
vault secrets enable database
SHASUM=$(sha256sum "./vault/file/atlas" | cut -d " " -f1)
vault write sys/plugins/catalog/database/atlas sha_256="$SHASUM" command="atlas"
vault write database/roles/readonly db_name=atlas creation_statements='{ "db": "admin", "roles": [{ "role": "readAnyDatabase" }] }' default_ttl="1h" max_ttl="24h" policies=atlas
vault write database/config/atlas plugin_name=atlas allowed_roles="readonly" apiID=$api_id apiKey=$api_key groupID=$group_id
vault read database/creds/readonly