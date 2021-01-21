import java

def ghidraal_import(name, globals=None, locals=None, fromlist=(), level=0):
    if _ghidraal_use_jythonic_imports:
        try:
            return _ghidraal_original_import(name, globals=globals, locals=locals, fromlist=fromlist, level=level)
        except ModuleNotFoundError as module_not_found:
            for pn in _ghidraal_package_names:
                # hide packages from the Jython JAR (see import logic in
                # Python's standard copy module, for example)
                if pn.startswith('org.python.'):
                    continue
                namedot = name + '.'
                if pn == name or pn.startswith(namedot):
                    # *** looks like name is a Java package name
                    if fromlist is None or len(fromlist)==0: # peel off first bit _after_ java
                        b = _ghidraal_original_import('java.%s' % name, globals=globals, locals=locals, fromlist=fromlist, level=level)
                        parts = name.split('.')
                        return getattr(b,parts[0])
                    else:
                        return _ghidraal_original_import('java.%s' % name, globals=globals, locals=locals, fromlist=fromlist, level=level)
            # try for a Java class name
            parts = name.split('.')[:1]
            if len(parts) > 0:
                if '.'.join(parts) in _ghidraal_package_names:
                    try:
                        t = java.type(name)
                        # *** looks like name is a Java class name
                        if fromlist is None or len(fromlist)==0: # peel off first bit _after_ java
                            b = _ghidraal_original_import('java.%s' % name, globals=globals, locals=locals, fromlist=fromlist, level=level)
                            parts = name.split('.')
                            return getattr(b,parts[0])
                        else:
                            return _ghidraal_original_import('java.%s' % name, globals=globals, locals=locals, fromlist=fromlist, level=level)
                    except BaseException:
                        pass  # fall through
            raise module_not_found
    else:
        return _ghidraal_original_import(name, globals=globals, locals=locals, fromlist=fromlist, level=level)

if '_ghidraal_use_jythonic_imports' not in globals():
    import builtins
    # fetch packages visible to GhidraScript's ClassLoader
    gs_classloader = java.type('ghidra.app.script.GhidraScript')['class'].getClassLoader()
    _ghidraal_package_names = [p.getName() for p in gs_classloader.getDefinedPackages()]
    _ghidraal_original_import = builtins.__import__
    _ghidraal_use_jythonic_imports = True
    builtins.__import__ = ghidraal_import

