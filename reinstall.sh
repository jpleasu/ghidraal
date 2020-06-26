#!/bin/bash
GHIDRA_INSTALL_DIR=./ghidra

echo Removing zips...
rm -f dist/*.zip

echo Building...
gradle

# clean
echo Removing any previous installation...
rm -f $GHIDRA_INSTALL_DIR/Extensions/Ghidra/*ghidraal*
rm -rf $GHIDRA_INSTALL_DIR/Ghidra/Extensions/ghidraal

# copy
echo Copying...
cp dist/*.zip $GHIDRA_INSTALL_DIR/Extensions/Ghidra/

# expand
unzip dist/*.zip -d $GHIDRA_INSTALL_DIR/Ghidra/Extensions/

