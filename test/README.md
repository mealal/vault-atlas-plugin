# Test the plugin in Hashicorp Vault 1.2.2 Docker image
The script uses Hashicorp image and install the _linux-amd64_ version of the plugin. You must build the plugin yourself before running the test. The Atlas clsuter connection details should be provided.

### Initial test
```
./start.sh --apiID=your_api_id --apiKey=your_api_key --groupID=your_group_id
```
The script will download image _vault_ and start container _hashicorp_vault_. As a result new temp user will be created.

### Getting more temp users
The follwoing command can be used to generate more tokens/users.
```
./new_token.sh
```
