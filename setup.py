from setuptools import setup, find_packages
from anchorecli import version

version = version.version

with open("requirements.txt") as f:
    requirements = f.read().splitlines()

package_name = "anchorecli"

description = "Anchore Service CLI"
long_description = open("README.rst").read()

url = "http://www.anchore.com"

package_data = {package_name: ["cli/*", "clients/*", "conf/*"]}

data_files = []
scripts = []

setup(
    name="anchorecli",
    author="Anchore Inc.",
    author_email="dev@anchore.com",
    license="Apache License 2.0",
    description=description,
    long_description=long_description,
    url=url,
    packages=find_packages(),
    version=version,
    data_files=data_files,
    include_package_data=True,
    package_data=package_data,
    entry_points="""
    [console_scripts]
    anchore-cli=anchorecli.cli:main_entry
    """,
    install_requires=requirements,
    scripts=scripts,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
)
