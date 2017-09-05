#!/bin/bash -x
set -e

python setup.py bdist_rpm --requires="python python-setuptools python2-clint PyYAML python-requests python-click pyOpenSSL python-jsonschema python-prettytable" --build-requires="python python-setuptools" --release="0"
python setup.py clean --all
