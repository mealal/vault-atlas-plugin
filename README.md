# vault-atlas-plugin

## Official plugin
I would recommend to test and use the official MongoDB Atals plugin. 
https://github.com/mongodb/vault-plugin-secrets-mongodbatlas

Support of this plugin is discontinued. 

## Description
Hashicorp Vault 1.2.2 Atlas Plugin

Used source code from https://github.com/desteves/mongodb-atlas-service-broker/

_dep_ support required https://github.com/golang/dep

### Build
The buld procedure requires Docker and uses clean Docker image to build the plugin for Linux and Mac. Plugin files will be placed into _build_ subfolder.
```
./docker_build.sh
```

### Old Build
Use this build if you don't want to use Docker. Plugin files will be placed into _build_ subfolder.
```
./build.sh
```
### Test the plugin
The plugin can be tested using the official Docker image from Hashicorp. Go to [test](https://github.com/mealal/vault-atlas-plugin/tree/master/test) for the details.

### Install
Identify the proper plugin file in *build* folder (atlas-darwin-386,atlas-darwin-amd64,atlas-linux-386,atlas-linux-amd64) and rename it to _atlas_
Place _atlas_ file into your plugins folder and run
```
vault secrets enable database
SHASUM=$(shasum -a 256 "./atlas" | cut -d " " -f1)
vault write sys/plugins/catalog/database/atlas sha_256="$SHASUM" command="atlas"
vault write database/roles/readonly db_name=atlas creation_statements='{ "db": "admin", "roles": [{ "role": "readAnyDatabase" }] }' default_ttl="1h" max_ttl="24h"
vault write database/config/atlas plugin_name=atlas allowed_roles="readonly" apiID="public API key" apiKey="private API key" groupID="group id"
```
### Security
If your system uses  _mlock_ you should allow it for the plugin
```
sudo setcap cap_ipc_lock=+ep /your_plugin_directory_path/atlas
```

### Test
```
vault read database/creds/readonly
```
