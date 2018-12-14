# phpsecscan

This will help you check your PHP project dependencies against the [CVE
compiled](https://github.com/FriendsOfPHP/security-advisories) by FriendsOfPHP.

It will analyze your `composer.lock` file and show if some versions are
affected by a vulnerability.

## Command line usage

Can be run standalone of as a server.

Usage:

```bash
phpsecscan
    [-port 8000]
    [-repo https://github.com/FriendsOfPHP/security-advisories.git]
    [-gitdir /tmp/XYZ]
    [-interval 600]
    [file]
```

Options:

- `gitdir` (defaults to some random temp dir): path to store CVE git checkout
- `h` or `help`: help usage
- `port` (default "8080"): server port
- `repo` (default "https://github.com/FriendsOfPHP/security-advisories.git"): CVE repository URL
- `server` (default false): start as a web server
- `interval` (default 600): refresh interval to sync CVEs

## Example

### Staring the server

```bash
./phpsecscan -gitdir ./cve
```

### Checking a local composer

```bash
curl localhost:8080/check --data @/path/to/project/composer.lock
```

## TODO

- github app
- gitlab app
- Vue.js front end


## See also

https://github.com/sensiolabs/security-checker
https://snyk.io/docs/snyk-for-php
https://github.com/marketplace/sonatype-depshield
https://ossindex.sonatype.org/

pkg:bitbucket/birkenfeld/pygments-main@244fd47e07d1014f0aed9c
