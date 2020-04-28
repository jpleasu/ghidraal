#!/bin/bash
GHIDRA_INSTALL_DIR=./ghidra

rm -f dist/*.zip

gradle

# clean
rm -f $GHIDRA_INSTALL_DIR/Extensions/Ghidra/*Ghidraal*
rm -rf $GHIDRA_INSTALL_DIR/Ghidra/Extensions/Ghidraal

# copy
cp dist/*.zip $GHIDRA_INSTALL_DIR/Extensions/Ghidra/

# expand
unzip dist/*.zip -d $GHIDRA_INSTALL_DIR/Ghidra/Extensions/

