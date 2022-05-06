# phpsecscan

This will help you check your PHP project dependencies against the [CVE
compiled](https://github.com/FriendsOfPHP/security-advisories) by FriendsOfPHP.

It will analyze your `composer.lock` file and show if some versions are
affected by a vulnerability.

## Install

You can install `phpsecscan` using:

- binenv (https://github.com/devops-works/binenv)
- using binaries in the [releases page](https://github.com/devops-works/phpsecscan/releases)
- using the docker image (https://hub.docker.com/r/devopsworks/phpsecscan)

## Build

### Local

```bash
make
```

### Docker

```bash
export VERSION=$(git describe --tags --always --dirty)
docker build . -t name/phpsecscan:${VERSION} --build-arg version=${VERSION} --build-arg builddate=$(date -u '+%Y%m%d.%H%M%S')
docker tag name/phpsecscan:${VERSION} name/phpsecscan:latest
```

## Usage

### Command line usage

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

### Docker

```bash
docker run -v /path/to/composer.lock:/composer.lock devopsworks/phpsecscan /composer.lock
```

## Example

### Single run mode

```bash
./phpsecscan composer.lock
```

### Starting the server

```bash
./phpsecscan -gitdir ./cve
```

### Checking a local composer

```bash
curl localhost:8080/check --data @/path/to/project/composer.lock
```

## TODO

- [ ] github app
- [ ] gitlab app
- [ ] Vue.js front end
- [ ] prometheus exporter

## See also

https://github.com/sensiolabs/security-checker
https://snyk.io/docs/snyk-for-php
https://github.com/marketplace/sonatype-depshield
https://ossindex.sonatype.org/
