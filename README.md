# openbao-database-plugin-oracle

An [OpenBao](https://www.openbao.org) plugin for Oracle.

For more information on this plugin, see the [Oracle Database Secrets Engine](https://developer.hashicorp.com/vault/docs/secrets/databases/oracle) page.

This project uses the database plugin interface introduced in OpenBao SDK API v2

This project does not use CGO or any native oracle client. Instead, it uses [go-ora](https://github.com/sijms/go-ora/v2); a pure go oracle client.

## Releases

This plugin supports the latest version of oracle which is v23 as of now.


## Build

`git clone` this repository and `go build -o vault-plugin-database-oracle ./plugin` from the project directory.

## Tests

`make test` will run a basic test suite against a Docker version of Oracle.

## Installation

**See [Case Sensitivity](#case-sensitivity) for important information about custom creation & rotation statements.**

The OpenBao plugin system is documented on the [OpenBao documentation site](https://openbao.org/docs/plugins/).

You will need to define a plugin directory using the `plugin_directory` configuration directive, then place the
`openbao-plugin-database-oracle` executable generated above in the directory.

Sample commands for plugin registration in current versions of Vault and starting to use the plugin:

```shell-session
$ bao plugin register -sha256=<SHA256 Hex value of the plugin binary> \
    database \                  # type
    openbao-plugin-database-oracle
Success! Registered plugin: vault-plugin-database-oracle
```

If running the plugin on MacOS you may run into an issue where the OS prevents the Oracle libraries from being executed.
See [How to open an app that hasn't been notarized or is from an unidentified developer](https://support.apple.com/en-us/HT202491)
on Apple's support website to be able to run this.

## Usage

### Case Sensitivity

It is important that you do NOT specify double quotes around the username in any of the SQL statements.
Otherwise Oracle may create/look up a user with the incorrect name (`foo_bar` instead of `FOO_BAR`).

### Default statements

The [rotation statements](https://openbao.org/docs/secrets/databases/custom/#:~:text=Expiration.Statements.Commands-,rotation_statements,-UpdateUserRequest.Password.Statements) are optional
and will default to `ALTER USER {{username}} IDENTIFIED BY "{{password}}"`

The [disconnect_statements](https://openbao.org/docs/secrets/databases/custom/#:~:text=revocation_statements) are optional and will default to the sql below. Setting `disconnect_statements` to `false` will disable the disconnect functionality, but should be disabled with caution since it may limit the effectiveness of revocation.

```sql
ALTER USER {{username}} ACCOUNT LOCK;
begin
  for x in ( select inst_id, sid, serial# from gv$session where username="{{username}}" )
  loop
   execute immediate ( 'alter system kill session '''|| x.Sid || ',' || x.Serial# || '@' || x.inst_id ''' immediate' );
  end loop;
  dbms_lock.sleep(1);
end;
DROP USER {{username}};
```
