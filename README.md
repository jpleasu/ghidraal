# Ghidraal

A Ghidra extension for scripting with GraalVM languages, including Javascript, Python3, R, and Ruby.

## setup

GraalVM is a drop in replacement for OpenJDK with some extra powers.

**Ghidraal will only work when Ghidra is run within a GraalVM!!!**


1. download GraalVM (20.0+) and set up set `JAVA_HOME`, `PATH`, etc.  You can
   copy and source [env.sh](/env.sh) for a hopefully painless install, e.g.
```
    mkdir ~/graalvm
    cp env.sh ~/graalvm
    cd ~/graalvm
    . env.sh
```

2. build or download
    - to build, you'll need gradle 5.  Create a symlink to your Ghidra
      installation and run gradle.  The extension will be generated in `dist`,
      e.g.
    ```bash
        # in the directory containing your checkout of this repo 
        ln -s ~/ghidra_9.1.2_PUBLIC ghidra
        . ~/graalvm/env.sh # must build with Graal available
        gradle
        ls dist/
    ```
    - or download here

3. Run ghidra with GraalVM and install the extension
```bash
    . ~/graalvm/env.sh
    ~/ghidra_9.1.2_PUBLIC/ghidraRun
```
From the main window, select `File->Install Extensions...`, check `Ghidraal` and restart Ghidra.

4. Open a program, select `File->Configure...` under `Experiment`, select
   `Configure`, and check `GhidraalPlugin`.


## usage

There are some extremely basic scripts for each supported language in the
[ghidra_scripts](/ghidra_scripts) directory.  When the extension is installed,
they should become visible in the Script Manager.

Note: Ghidraal hijacks the `.py` extension by unloading the Jython script
provider!  Disable `GhidraalPlugin` to reenable Jython.

Note: *Most* of Ghidra's built in Python scripts would need porting to Python 3.

