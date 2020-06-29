def dump(f):
  print(f'{f.getEntryPoint().toString()} {f.getName()}')

currentProgram.getFunctionManager().getFunctions(True).forEach(dump)

import sys
printf('sys.version = %s\n' % sys.version)

