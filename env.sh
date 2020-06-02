D="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && cd -P "$( dirname "$SOURCE" )" && pwd )"
 
ver=20.1.0
if [ ! -d $D/graalvm-ce-java11-${ver} ]; then
  pushd $D
  wget https://github.com/graalvm/graalvm-ce-builds/releases/download/vm-${ver}/graalvm-ce-java11-linux-amd64-${ver}.tar.gz
  tar -zxvf graalvm-ce-java11-linux-amd64-${ver}.tar.gz
  ln -s graalvm-ce-java11-${ver} graalvm
  ./graalvm/bin/gu install native-image python ruby r
  popd
fi
 
export JAVA_HOME="$D/graalvm"
export PATH="$D/graalvm/bin:$PATH"
export LLVM_TOOLCHAIN=$(lli --print-toolchain-path)
export PATH="$LLVM_TOOLCHAIN:$PATH"
export LD_LIBRARY_PATH="$D/graalvm/languages/R/lib:$D/graalvm/languages/llvm/native/lib:$LD_LIBRARY_PATH"

