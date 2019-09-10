#! /bin/bash
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

docker run -d --name hashicorp_vault --cap-add=IPC_LOCK -e 'VAULT_API_ADDR=http://127.0.0.1:8200' -e 'VAULT_LOCAL_CONFIG={"backend": {"file": {"path": "/vault/file"}}, "listener": {"tcp":{"address": "0.0.0.0:8200","tls_disable": 1}}, "default_lease_ttl": "1h", "max_lease_ttl": "1h","plugin_directory":"/vault/file","log_level":"DEBUG"}' vault:1.2.2 server
rm -f ./atlas
cp ../build/atlas-linux-amd64 ./atlas
docker cp ./atlas hashicorp_vault:/vault/file/
docker cp ./scripts/init.sh hashicorp_vault:/
docker cp ./scripts/get_creds.sh hashicorp_vault:/
docker exec hashicorp_vault sh ./init.sh --apiID="$api_id" --apiKey="$api_key" --groupID="$group_id"