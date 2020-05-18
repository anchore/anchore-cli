#!/bin/bash -x
set -e

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ci/utils"

print_colorized INFO "Package Anchore CLI for MacOS."; echo

print_colorized INFO "Check whether we are executing on MacOS. Exit/fail if not."; echo

uname -s | grep Darwin

export VIRTUALENV_DIR="anchore_virtualenv"
export DIST_PATH="macos-bin"

# Install pip if not installed
if ! which pip > /dev/null; then
    print_colorized INFO "Installing pip."; echo
    sudo easy_install pip
fi

# Install virtualenv if not installed
if ! which virtualenv > /dev/null; then
    print_colorized INFO "Installing virtualenv."; echo
    sudo easy_install virtualenv
fi

print_colorized INFO "Creating virtualenv."; echo
virtualenv $VIRTUALENV_DIR

print_colorized INFO "Setting up virtualenv."; echo
$VIRTUALENV_DIR/bin/pip install pyinstaller anchorecli

print_colorized INFO "Installing for distribution."; echo
# Compile anchore-cli script into distributable bundle
$VIRTUALENV_DIR/bin/pyinstaller --log-level=ERROR --noconfirm --onefile --distpath $DIST_PATH $VIRTUALENV_DIR/bin/anchore-cli

# If you want to create an archive
# if [ -f anchore-cli-macos.zip ]; then
#     rm anchore-cli-macos.zip
# fi
# zip -r -X anchore-cli-macos.zip $DIST_PATH

print_colorized INFO "Cleaning up."; echo

rm -rf $VIRTUALENV_DIR build
rm anchore-cli.spec
