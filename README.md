# keyster

An SSH authorized key store for use with OpenSSH AuthorizedKeysCommand

## Binary Downloads

[![Gobuild Download](http://gobuild.io/badge/github.com/sivel/keyster/download.png)](http://gobuild.io/github.com/sivel/keyster)

## Example Execution

```
./keyster -ldap-server ldap.itd.umich.edu:389 -ldap-base-dn dc=umich,dc=edu -key-allow-options -key-duration 720h
```

## Configuration File

The optional configuration file is located at `/etc/keyster.yaml`

Full configuration example:

```
server:
	port: ":8000"
	cert: /path/to/ssl.crt
	key: /path/to/ssl.key
	logfile: /var/log/keyster.log
	secret: "\xd6+Ke\xf9\xf2}a\xa6\xab\xc1su>P\x03\xea\x7f\x18U\xbe\x0b\x8b\x04"
mongo:
	url: "mongodb://127.0.0.1:27017/keyster"
ldap:
	server: "ldap.itd.umich.edu:636"
	basedn: "dc=umich,dc=edu"
	ssl: true
key:
	duration: 720h
	allowoptions: true
```

Arguments provided on the command line will override the configuration file. Keep in mind that `-ldap-ssl` and `-key-allow-options` work slightly different, in that they must be supplied to enable the functionality. Not providing them will not disable their respective functionality if explicitly enabled in the configuration file.

### Secret

The `secret` option of `server` allows you to provide a string to be used in authenticating the user sessions. If not provided, each time keyster starts, a new secret will be generated, invalidating user sessions.

It is recommended that you define a secret if you are using multiple servers, otherwise the individual servers will be unable to uthenticate user sessions.

## Usage with AuthorizedKeysCommand

The `AuthorizedKeysCommand` expects an executable that takes a single argument, which is the username to retrieve the keys for. An example executable may look like:

```bash
#!/bin/bash
curl -sf http://keyserver.example.org:3000/users/$1/keys
```

Name this file something like `/usr/local/bin/userkeys.sh` and make it executable: `chmod a+x /usr/local/bin/userkeys.sh`

Now add the following to your `/etc/sshd/sshd_config` file:

```
AuthorizedKeysCommand      /usr/local/bin/userkeys.sh
AuthorizedKeysCommandUser  nobody
```

*Most operating systems have a nobody user, but you can replace that user with any non-root user that is different from the user running OpenSSH on the server. This should preferably be a user not already in use by another daemon.*

Now, when a user logs in, `userkeys.sh` will be executed and if there are keys for that user they will be returned by our simple script.

## See Also

[Better SSH Authorized Keys Management](https://gist.github.com/sivel/c68f601137ef9063efd7)
