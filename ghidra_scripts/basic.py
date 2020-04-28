import sys

printf('sys.version = %s\n' % sys.version)


from ghidra.util import Msg
Msg.showError(None, None, "title", "omg omg!")

s=askString('sup', 'gimme string')
print('got s=%s' % s)

