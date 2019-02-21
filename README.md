# vault-atlas-plugin
Hashicorp Vault Atlas Plugin

Used source code from https://github.com/desteves/mongodb-atlas-service-broker/

### Build
```
go build -o vault-atlas-plugin ./mongodb-atlas-plugin/main.go
```

### Install
Place vault-atlas-plugin file into your plugins folder and run
```
SHASUM=$(shasum -a 256 "./vault-atlas-plugin" | cut -d " " -f1)
vault write sys/plugins/catalog/database/vault-atlas-plugin sha_256="$SHASUM" command="vault-atlas-plugin"
vault write database/config/vault-atlas-plugin plugin_name=vault-atlas-plugin allowed_roles="readonly" apiID="public API key" apiKey="private API key" groupID="group id"
```

### Test
```
vault read database/creds/readonly
```
