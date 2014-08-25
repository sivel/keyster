# keyster

An SSH authorized key store for use with OpenSSH AuthorizedKeysCommand

## Binary Downloads

[![Gobuild Download](http://gobuild.io/badge/github.com/sivel/keyster/download.png)](http://gobuild.io/github.com/sivel/keyster)

## Example Execution

```
./keyster -ldap-server ldap.itd.umich.edu:389 -ldap-base-dn dc=umich,dc=edu -key-allow-options -key-duration 720h
```

## Usage with AuthorizedKeysCommand

The `AuthorizedKeysCommand` expects an executable that takes a single argument, which is the username to retrieve the keys for.  An example executable may look like:

```bash
#!/bin/bash
curl -sf http://keyserver.example.org:3000/users/$1/keys
```

Name this file something like `/usr/local/bin/userkeys.sh` and make it executable: `chmod a+x /usr/local/bin/userkeys.sh`

Now add the following to your `/etc/sshd/sshd\_config` file:

```
AuthorizedKeysCommand      /usr/local/bin/userkeys.sh
AuthorizedKeysCommandUser  nobody
```

*Most operating systems have a nobody user, but you can replace that user with any non-root user that is different from the user running OpenSSH on the server. This should preferably be a user not already in use by another daemon.*

Now, when a user logs in, `userkeys.sh` will be executed and if there are keys for that user they will be returned by our simple script.

## See Also

[Better SSH Authorized Keys Management](https://gist.github.com/sivel/c68f601137ef9063efd7)
