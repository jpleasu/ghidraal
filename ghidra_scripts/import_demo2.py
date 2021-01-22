# Demonstration of imports _without_ Ghidraal's import magic. 
#@category Ghidraal

_ghidraal_use_jythonic_imports = False
# subsequent import statements rely on GraalPython's Python module "java" to
# import Java packages and classes

from java.ghidra.util import Msg
Msg.showInfo(None, None, '1', '1')

from java.ghidra.util import Msg as MyMsg
MyMsg.showInfo(None, None, '2', '2')

import java.ghidra.util.Msg
java.ghidra.util.Msg.showInfo(None, None, '3', '3')

import java.ghidra.util.Msg as MyOtherMsg
MyOtherMsg.showInfo(None, None, '4', '4')

import java.ghidra.util
java.ghidra.util.Msg.showInfo(None, None, '5', '5')

import java.ghidra.util as myutil
myutil.Msg.showInfo(None, None, '6', '6')

