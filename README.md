# elastic-glauth

## What it does

This tool exports users and password hashes from Elasticsearch into the super lightweight LDAP server glauthd.

* Read glauthd configuration template in to a new configuration string
* Fetch all roles from Elasticsearch which have a metadata entry called glauth_gid
* Fetch all users from Elasticsearch which are member of any previously fetched roles
* Iterate over all fetched users and:
  * persist users in a JSON userdb to assign unique uids
**  * append a config section for each user to the new configuration string
* Compare old and new configuration, write new configuration over old when changed

## Configuration

```
RUST_LOG=info
ELASTICSEARCH_URL="http://127.0.0.1:9200"
ELASTICSEARCH_USER="username"
ELASTICSEARCH_PASSWORD='password'
GLAUTH_MIN_UID=5100
GLAUTH_PRIMARY_GROUP=5000
GLAUTH_CONFIG_PATH="/path/to/glauth.cfg"
GLAUTH_CONFIG_TEMPLATE_PATH="/path/to/glauth.cfg.tpl"
```

## Run

```
# simple
./elastic-glauth elastic-glauth.cfg

# cron with flock
flock -w 30 /path/to/elastic-glauth /path/to/elastic-glauth /path/to/elastic-glauth.cfg >> /path/to/elastic-glauth.log 2>&1
```
