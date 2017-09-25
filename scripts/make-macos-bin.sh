#!/bin/bash -x
set -e

echo "Check we're on Mac OS before continuing..."
uname -s | grep Darwin

export VIRTUALENV_DIR="anchore_virtualenv"
export DIST_PATH="macos-bin"

# Install pip if not installed
if ! which pip > /dev/null; then
    sudo easy_install pip
fi

# Install virtualenv if not installed
if ! which virtualenv > /dev/null; then
    sudo easy_install virtualenv
fi

# Create a new python virtual environment
virtualenv $VIRTUALENV_DIR

# Install required packages into the virtual environment
$VIRTUALENV_DIR/bin/pip install pyinstaller anchorecli

# Compile anchore-cli script into distributable bundle
$VIRTUALENV_DIR/bin/pyinstaller --log-level=ERROR --noconfirm --onefile --distpath $DIST_PATH $VIRTUALENV_DIR/bin/anchore-cli

# If you want to create an archive
# if [ -f anchore-cli-macos.zip ]; then
#     rm anchore-cli-macos.zip
# fi
# zip -r -X anchore-cli-macos.zip $DIST_PATH

# Cleanup
rm -rf $VIRTUALENV_DIR build
rm anchore-cli.spec
