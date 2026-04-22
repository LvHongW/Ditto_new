#!/bin/bash

if [ $# -ne 2 ]; then
  echo "Usage ./syz-compile-arm64.sh case_path arch"
  exit 1
fi

CASE_PATH=$1
SYZ_PATH=$CASE_PATH/gopath/src/github.com/google/syzkaller
ARCH=$2
PROJECT_PATH=`pwd`

export GO111MODULE=auto
export GOTOOLCHAIN=local
unset GOBIN
export GOBIN=
export GOPATH=$CASE_PATH/gopath
export GOROOT=$PROJECT_PATH/tools/goroot
export LLVM_BIN=$PROJECT_PATH/tools/llvm/build/bin
export TMPDIR=$CASE_PATH/.tmp
export TMP=$TMPDIR
export TEMP=$TMPDIR
export GOTMPDIR=$TMPDIR
export GOCACHE=$CASE_PATH/.gocache
mkdir -p "$TMPDIR" "$GOCACHE"
export PATH=$GOROOT/bin:$LLVM_BIN:$PATH

cd $SYZ_PATH
make generate || exit 1
rm CorrectTemplate
make TARGETARCH=$ARCH TARGETVMARCH=arm64 || exit 1
exit 0
