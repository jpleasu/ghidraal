import java

java.sys.stdout=_gsout
java.sys.stderr=_gserr

class Cls:
  def _import(self, name, *args, **kwargs):
    try:
      m=original_import(name, *args, **kwargs)
      return m
    except:
      name='java.%s' % name
      #print('name=%s args=%s kwargs=%s' % (name, args, kwargs))
      return original_import(name, *args, **kwargs)

import builtins
if not hasattr(builtins, '_iwhack'):
  original_import = builtins.__import__
  builtins.__import__ = Cls()._import
  builtins._iwhack=True

