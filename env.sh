# Graalvm sourcable script
## To download GraalVM and install some components:
##   from a bash shell
##   1. create a new directory, e.g.
##      mkdir ~/graalvm
##   2. copy or link this script to that new directory, e.g.  
##      cp ~/git/graalvm/env.sh ~/graalvm
##      #  OR
##      ln-s ~/git/graalvm/env.sh ~/graalvm
##   3. from that directory, source env.sh
##      cd ~/graalvm
##      . env.sh
##   4. environment should be set to use GraalVM
##      which java #  ~/graalvm/jdk/bin/java
##      which lli  #  ~/graalvm/jdk/bin/lli
##      gu list    #  lists components including Graal.js, FastR, and Graal.Python
##
## To setup environment after install, source ~/jdk/env.sh from anywhere.

D="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd -P "$( dirname "$SOURCE" )" && pwd )"
 
ver=21.0.0
tarball="graalvm-ce-java11-linux-amd64-${ver}.tar.gz"
linkname="jdk"
jdk_dirname="graalvm-ce-java11-${ver}"


install=1
clean=0
toolchain_path=1

if [ $# -gt 0 ]; then
  case $1 in
    reinstall) clean=1;install=1;;
    clean) clean=1;install=0;;
    no-toolchain-path) toolchain_path=0;;
    *) echo "Unrecognized argument \"$1\"";return 1;;
  esac
fi

if [ $clean -eq 1 ]; then
    echo "Cleaning GraalVM $ver env"
    pushd "$D" > /dev/null
    rm -f "${tarball}" "${linkname}"
    rm -rf "${jdk_dirname}"
    unset _GRAAL_ENV
    popd > /dev/null
fi

if [ $install -ne 1 ]; then
  return 0;
fi


##  add environment variable to notify on repeated sourcing times
if [ ! -z "${_GRAAL_ENV}" ]; then
  echo "GraalVM $ver env already set: \"${_GRAAL_ENV}\""
  return 1
fi
export _GRAAL_ENV="$D"


## if this version isn't installed, install it
if [ ! -d "$D/graalvm-ce-java11-${ver}" ]; then
  echo "Installing GraalVM $ver env"
  pushd "$D" > /dev/null
  ## cleanup existing symlink
  if [ -f "${linkname}" ]; then 
    if [ -L "${linkname}" -a -d "${linkname}" ]; then
        rm -f "${linkname}"
    else
        echo "\"${linkname}\" exists, but isn't a link to a directory"
        return 1
    fi
  fi
  wget "https://github.com/graalvm/graalvm-ce-builds/releases/download/vm-${ver}/${tarball}"
  tar -zxvf "${tarball}"
  ln -s "${jdk_dirname}" "${linkname}"
  ./${linkname}/bin/gu install llvm-toolchain native-image python ruby R
  rm -f "${tarball}"
  popd > /dev/null
fi
 
echo "Setting environment for GraalVM $ver"

## assuming env exists, set vars
export PATH="$D/${linkname}/bin:$PATH"
export JAVA_HOME="$D/${linkname}"
export LD_LIBRARY_PATH="$D/${linkname}/languages/R/lib:$D/${linkname}/languages/llvm/native/lib:$LD_LIBRARY_PATH"

if [ $toolchain_path -eq 1 ]; then
  ## add toolchain to path
  lli_path=$(which lli)
  if [ ! -x "${lli_path}" ] ; then
    unset _GRAAL_ENV
    echo "  lli executable missing!"
    echo "  Try to reinstall GraalVM $ver env with"
    echo "      cd \"$D\""
    echo "      . env.sh reinstall"
    return 1
  fi

  export LLVM_TOOLCHAIN=$(lli --print-toolchain-path)
  export PATH="$LLVM_TOOLCHAIN:$PATH"
fi


