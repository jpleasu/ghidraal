# Demonstration of Ghidraal's import magic. 
#@category Ghidraal

from ghidra.util import Msg
Msg.showInfo(None, None, '1', '1')

from ghidra.util import Msg as MyMsg
MyMsg.showInfo(None, None, '2', '2')

import ghidra.util.Msg
ghidra.util.Msg.showInfo(None, None, '3', '3')

import ghidra.util.Msg as MyOtherMsg
MyOtherMsg.showInfo(None, None, '4', '4')

import ghidra.util
ghidra.util.Msg.showInfo(None, None, '5', '5')

import ghidra.util as myutil
myutil.Msg.showInfo(None, None, '6', '6')


