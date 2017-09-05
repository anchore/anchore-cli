#!/bin/bash -x

set -e

apt-get install python-stdeb python-pip dh-python

python setup.py --command-packages=stdeb.command sdist_dsc --debian-version "0" --depends "python-requests,python-click,python-clint,python-prettytable,python-yaml,python-colorama,python-args,python-websocket,libyaml-0-2,python-jsonschema" bdist_deb
python setup.py clean --all
rm -rf anchore-*.tar.gz dist/ anchore.egg-info/
mv deb_dist dist
