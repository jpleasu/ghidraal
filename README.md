# Ghidraal

A Ghidra extension for scripting with GraalVM languages, including Javascript, Python3, R, and Ruby.

## setup

GraalVM is a drop in replacement for OpenJDK with some extra powers.

**Ghidraal will only work when Ghidra is run within a GraalVM!!!**


1. download GraalVM (20.1+) and set up set `JAVA_HOME`, `PATH`, etc.  You can
   copy and source [env.sh](/env.sh) for a hopefully painless install, e.g.
    ```
    mkdir ~/graalvm
    cp env.sh ~/graalvm
    cd ~/graalvm
    . env.sh
    ```

2. build or download
    - to build, you'll need gradle 5+.  Create a symlink to your Ghidra
      installation and run gradle.  The extension will be generated in `dist`,
      e.g.
        ```bash
        # in the directory containing your checkout of this repo 
        ln -s ~/ghidra_9.2.1_PUBLIC ghidra
        . ~/graalvm/env.sh # build requires GraalVM
        gradle
        ls dist/
        ```
    - or download a [release](/../../releases)

3. Run ghidra with GraalVM and install the extension
    ```bash
    . ~/graalvm/env.sh
    ~/ghidra_9.2.1_PUBLIC/ghidraRun
    ```
    From the main window, select `File->Install Extensions...`, click the `+`,
    and select the ghidraal release zip file.

4. Restart Ghidra

5. Open a program.  If not prompted to, select `File->Configure...`, under
   `Experimental` select `Configure`, and make sure `GhidraalPlugin` is
   checked.

## usage

There are some extremely basic scripts for each supported language in the
[ghidra_scripts](/ghidra_scripts) directory.  When the extension is installed,
they should become visible in the Script Manager in the Ghidraal category.

An interactive console for each language is available under the code browser "Window"
menu option.

Note: Ghidraal hijacks the `.py` extension by unloading the Jython script
provider!  Disable `GhidraalPlugin` to reenable Jython.

Note: Ghidra's built in Python scripts are Python 2, so won't necessarily work
with Ghidraal's Python 3.  Some can be ported automatically with `2to3`.



# changelog

- ghidraal-0.0.3
    - added support for analyzeHeadless usage
    - move example scripts into Ghidraal category
- ghidraal-0.0.2
    - added interactive consoles
    - made basic.py like the other basic scripts
- ghidraal-0.0.1
    - initial

