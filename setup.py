#!/usr/bin/python
from setuptools import setup, find_packages
import os, shutil, errno
from anchorecli import version

version =  version.version

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

package_name = "anchorecli"

description = 'Anchore Service CLI'
long_description = open('README.rst').read()

url = 'http://www.anchore.com'

#package_data = {}
package_data = {
    package_name: [
        'cli/*',
        'clients/*',
        'conf/*'
    ]
}

#data_files = [('conf', ['conf/config.yaml.example'])]
data_files = []
#data_files = [('datafiles', ['datafiles/lynis-data.tar'])]
#data_files = [
#    ('twisted', ['anchore_service/twisted/*'])
#]
#packages=find_packages(exclude=('run*', 'log*', 'conf*', 'dead*', 'scripts/*')),
#scripts = ['scripts/anchore-service.sh', 'scripts/anchore-service']
scripts = []

setup(
    name='anchorecli',
    author='Anchore Inc.',
    author_email='dev@anchore.com',
    license='Apache License 2.0',
    description=description,
    long_description=long_description,
    url=url,
    packages=find_packages(),
    version=version,
    data_files=data_files,
    include_package_data=True,
    package_data=package_data,
    entry_points='''
    [console_scripts]
    anchore-cli=anchorecli.cli:main_entry
    ''',
    install_requires=requirements,
    scripts=scripts
)
#    entry_points='''
#    [console_scripts]
#    anchore=anchore.cli:main_entry
#    ''',
