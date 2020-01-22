from setuptools import setup, find_packages
from anchorecli import version

version = version.version

with open('requirements.txt') as f:
    requirements = f.read().splitlines()

package_name = "anchorecli"

description = 'Anchore Service CLI'
long_description = open('README.rst').read()

url = 'http://www.anchore.com'

package_data = {
    package_name: [
        'cli/*',
        'clients/*',
        'conf/*'
    ]
}

data_files = []
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
