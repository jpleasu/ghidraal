# Ghidraal

A Ghidra extension for scripting with GraalVM languages, including Javascript, Python3, R, and Ruby.

## setup

GraalVM is a drop in replacement for OpenJDK with some extra powers.

**Ghidraal will only work when Ghidra is run within a GraalVM!!!**


1. download GraalVM (20.1+) and set up set `JAVA_HOME`, `PATH`, etc.  You can
   copy and source [env.sh](/env.sh) for a hopefully painless install, e.g.
    ```bash
    mkdir ~/graalvm
    cp env.sh ~/graalvm
    cd ~/graalvm
    . env.sh
    ```

2. build or download the Ghidraal extension
    - to build, you'll need gradle 5+.  Create a symlink to your Ghidra
      installation and run gradle.  The extension will be generated in `dist`,
      e.g.
        ```bash
        # in the directory containing your checkout of this repo 
        ln -s ~/ghidra_9.2.2_PUBLIC ghidra
        . ~/graalvm/env.sh # build requires GraalVM
        gradle
        ls dist/
        ```
    - or download a [release](/../../releases)

3. Run ghidra with GraalVM and install the extension
    ```bash
    . ~/graalvm/env.sh
    ~/ghidra_9.2.2_PUBLIC/ghidraRun
    ```
    From the main window, select `File->Install Extensions...`, click the `+`,
    and select the Ghidraal release zip file from the repo `dist` directory.

4. Restart Ghidra

5. Open a program.  If not prompted to, select `File->Configure...`, under
   `Experimental` select `Configure`, and make sure `GhidraalPlugin` is
   checked.

## usage

There are some extremely basic scripts for each supported language in the
[ghidra_scripts](/ghidra_scripts) directory.  When the extension is installed,
they should become visible in the Script Manager under the Ghidraal category.

An interactive console for each language is available under the code browser "Window"
menu option.

### Python

Ghidraal hijacks the `.py` extension by removing the Jython script provider.
Disable `GhidraalPlugin` to reenable Jython.

Ghidra's built in Python scripts are Python 2, so won't necessarily work with
Ghidraal's Python 3.  Some can be ported automatically with `2to3`.

For more on Graal Python, see the
[README.md](https://github.com/oracle/graalpython/blob/master/README.md).

#### import magic

Jython provides some import magic so that Java packages and classes can be
imported like Python modules.  Ghidraal implements a similar magic to emulate
this behavior (*independent from* the Graal Python `--python.EmulateJython`
switch implementation).  See [import_demo.py](ghidra_scripts/import_demo.py).

To disable Ghidraal's import magic, set the (script/interpreter) global
variable `_ghidraal_use_jythonic_imports` to `False`. See
[import_demo2.py](ghidra_scripts/import_demo2.py).

#### packages
Ghidraal imports `site` automatically, so installed packages will be available.

```bash
# to see what's available
graalpython -m ginstall install --help
# install pandas
graalpython -m ginstall install pandas

# after an upgrade of GraalVM, it might be necessary to reinstall packages
graalpython -m ginstall uninstall numpy,pandas
graalpython -m ginstall install pandas

# although pip isn't 100% supported, some packages can be installed, e.g.
graalpython -m ginstall pypi pyelftools
```



# Ghidraal changelog

- ghidraal-0.0.4
    - don't run GhidraalScripts in swing thread
    - fix memory leak from unclosed polyglot contexts
    - console
        - don't print expression value if it's (equivalent of) null
        - add "busy" prompt indicator
    - python
        - fix Jython import emulation, update docs, add examples
        - use option "python.ForceImportSite" to automatically import site.py
- ghidraal-0.0.3
    - added support for analyzeHeadless usage
    - move example scripts into Ghidraal category
- ghidraal-0.0.2
    - added interactive consoles
    - made basic.py like the other basic scripts
- ghidraal-0.0.1
    - initial

