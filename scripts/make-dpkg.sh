#!/bin/bash -x

set -e

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ci/utils"

print_colorized INFO "Package Anchore CLI for Debian-based distros."; echo

print_colorized INFO "Installing dependencies."; echo

# TODO determine whether these packages are available, or if etc. 
# python3-stdeb is required
# TODO install -y ?
apt-get install python-stdeb python-pip dh-python

print_colorized INFO "Installing for distribution."; echo

python setup.py --command-packages=stdeb.command sdist_dsc --debian-version "0" --depends "python-requests,python-click,python-clint,python-prettytable,python-yaml,python-colorama,python-args,python-websocket,libyaml-0-2,python-jsonschema" bdist_deb
python setup.py clean --all

print_colorized INFO "Cleaning up."; echo

rm -rf anchore-*.tar.gz dist/ anchore.egg-info/
mv deb_dist dist
