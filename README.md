# vault-atlas-plugin
Hashicorp Vault Atlas Plugin

Used source code from https://github.com/desteves/mongodb-atlas-service-broker/

dep support required https://github.com/golang/dep

### Build
```
dep ensure
go build -o atlas ./mongodb-atlas-plugin/main.go
```

### Install
Place atlas file into your plugins folder and run
```
vault secrets enable database
SHASUM=$(shasum -a 256 "./atlas" | cut -d " " -f1)
vault write sys/plugins/catalog/database/atlas sha_256="$SHASUM" command="atlas"
vault write database/roles/readonly db_name=atlas creation_statements='{ "db": "admin", "roles": [{ "role": "readAnyDatabase" }] }' default_ttl="1h" max_ttl="24h"
vault write database/config/atlas plugin_name=atlas allowed_roles="readonly" apiID="public API key" apiKey="private API key" groupID="group id"
```
### Security
If your system uses  ```mlock``` you should allow it for the plugin
```
sudo setcap cap_ipc_lock=+ep /your_plugin_directory_path/atlas
```

### Test
```
vault read database/creds/readonly
```
