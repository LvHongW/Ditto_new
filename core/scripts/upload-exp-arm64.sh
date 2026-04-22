#!/bin/bash

set -ex
echo "running upload-exp-arm64.sh"

if [ $# -ne 10 ]; then
  echo "Usage ./upload-exp-arm64.sh case_path syz_repro_url ssh_port image_path syz_commit type c_repro i386 fixed gcc_version"
  exit 1
fi

CASE_PATH=$1
TESTCASE=$2
PORT=$3
IMAGE_PATH=$4
SYZKALLER=$5
TYPE=$6
C_REPRO=$7
I386=$8
FIXED=$9
GCCVERSION=${10}
EXITCODE=3
PROJECT_PATH=`pwd`
BIN_PATH=$CASE_PATH/gopath/src/github.com/google/syzkaller
export GO111MODULE=auto
export GOTOOLCHAIN=local
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

ARCH="arm64"

# Try to find the cross-compiler, reusing the toolchain from deploy-arm64.sh.
CROSS_PREFIX=""
if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
  CROSS_PREFIX="aarch64-linux-gnu-"
elif command -v aarch64-none-linux-gnu-gcc >/dev/null 2>&1; then
  CROSS_PREFIX="aarch64-none-linux-gnu-"
else
  for tc in "$PROJECT_PATH"/tools/aarch64-gcc-{12.3,11.3,10.3}/bin "$PROJECT_PATH"/tools/linaro-gcc-7.5/bin; do
    if [ -x "$tc/aarch64-none-linux-gnu-gcc" ]; then
      export PATH="$tc:$PATH"
      CROSS_PREFIX="aarch64-none-linux-gnu-"
      break
    elif [ -x "$tc/aarch64-linux-gnu-gcc" ]; then
      export PATH="$tc:$PATH"
      CROSS_PREFIX="aarch64-linux-gnu-"
      break
    fi
  done
fi

function check_arm64_toolchain() {
    if [ -z "$CROSS_PREFIX" ]; then
        echo "[!] No arm64 cross toolchain found for syzkaller executor build."
        echo "[!] Install on Ubuntu/Debian: sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu"
        exit 1
    fi
    local missing=0
    local bins=(
        "${CROSS_PREFIX}gcc"
        "${CROSS_PREFIX}objdump"
        "${CROSS_PREFIX}ld"
    )
    for b in "${bins[@]}"; do
        if ! command -v "$b" >/dev/null 2>&1; then
            echo "[!] Missing required tool: $b"
            missing=1
        fi
    done
    if [ "$missing" -ne 0 ]; then
        echo "[!] Arm64 syzkaller executor build requires cross toolchain."
        exit 1
    fi
    echo "[+] Using arm64 cross prefix: $CROSS_PREFIX"
}

cd $CASE_PATH
if [ ! -d "$CASE_PATH/poc" ]; then
    mkdir $CASE_PATH/poc
fi

cd $CASE_PATH/poc

if [ "$TYPE" == "1" ]; then
    cp $TESTCASE ./testcase || exit 1
else
    cp $CASE_PATH/basic_info/syz_repro ./testcase
fi
scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $IMAGE_PATH/stretch.img.key -P $PORT ./testcase root@localhost:/root

if [ "$FIXED" == "0" ]; then
    check_arm64_toolchain

    # First, try to reuse the syzkaller binaries already built by deploy-arm64.sh.
    DEPLOY_BIN_DIR="$CASE_PATH/gopath/src/github.com/google/syzkaller/bin/linux_$ARCH"
    if [ -f "$DEPLOY_BIN_DIR/syz-execprog" ] && [ -f "$DEPLOY_BIN_DIR/syz-executor" ]; then
        echo "[+] Reusing syzkaller binaries from deploy step: $DEPLOY_BIN_DIR"
        cp "$DEPLOY_BIN_DIR/syz-execprog" "$CASE_PATH/poc/"
        cp "$DEPLOY_BIN_DIR/syz-executor" "$CASE_PATH/poc/"
        BIN_PATH=$CASE_PATH/poc
    else
        # Fall back to building syzkaller in the poc directory.
        if [ ! -d "$CASE_PATH/poc/gopath" ]; then
            mkdir -p $CASE_PATH/poc/gopath
        fi
        export GOPATH=$CASE_PATH/poc/gopath
        mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
        BIN_PATH=$CASE_PATH/poc
        cd $GOPATH/src/github.com/google/
        if [ ! -d "$GOPATH/src/github.com/google/syzkaller" ]; then
            cp -r $PROJECT_PATH/tools/gopath/src/github.com/google/syzkaller ./
            cd $GOPATH/src/github.com/google/syzkaller || exit 1

            # Use Ditto's syzkaller version (9b1f3e6) — the same commit that
            # deploy-arm64.sh checks out and patches.  Using the case's arbitrary
            # syzkaller commit can fail because newer go.mod files may contain
            # "tool" blocks that require a Go version not available when
            # GOTOOLCHAIN=local is set.
            git checkout -f 9b1f3e665308ee2ddd5b3f35a078219b5c509cdb || {
                echo "[!] Failed to checkout Ditto syzkaller base commit 9b1f3e6"
                exit 1
            }

            # Apply the Ditto patch (same as deploy-arm64.sh).
            PATCHES_PATH=$PROJECT_PATH/core/patches
            patch -p1 -i $PATCHES_PATH/syzkaller-9b1f3e6-ditto.patch

            # Clean arm image build artifacts that may contain special device files.
            for artifact in stretch-arm64 wheezy-arm64 trixie-arm64; do
                if [ -e "$artifact" ]; then
                    sudo rm -rf "$artifact" || rm -rf "$artifact" 2>/dev/null || true
                fi
            done

            make TARGETARCH=$ARCH TARGETVMARCH=arm64 execprog executor
            if [ -d "bin/linux_$ARCH" ]; then
                cp bin/linux_$ARCH/syz-execprog $BIN_PATH
                cp bin/linux_$ARCH/syz-executor $BIN_PATH
            else
                cp bin/syz-execprog $BIN_PATH
                cp bin/syz-executor $BIN_PATH
            fi
            touch MAKE_COMPLETED
        else
            for i in {1..20}
            do
                if [ -f "$GOPATH/src/github.com/google/syzkaller/MAKE_COMPLETED" ]; then
                    break
                fi
                sleep 10
            done
            if [ ! -f "$GOPATH/src/github.com/google/syzkaller/MAKE_COMPLETED" ]; then
                echo "[!] Time out waiting for syzkaller compilation to finish, or previous build aborted"
                exit 1
            fi
        fi
    fi
else
    cd $CASE_PATH/gopath/src/github.com/google/syzkaller
fi

if [ ! -f "$BIN_PATH/syz-execprog" ]; then
    SYZ_PATH=$CASE_PATH/poc/gopath/src/github.com/google/syzkaller/
    if [ -d "$SYZ_PATH/bin/linux_$ARCH" ]; then
        cp $SYZ_PATH/bin/linux_$ARCH/syz-execprog $BIN_PATH
        cp $SYZ_PATH/bin/linux_$ARCH/syz-executor $BIN_PATH
    else
        cp $SYZ_PATH/bin/syz-execprog $BIN_PATH
        cp $SYZ_PATH/bin/syz-executor $BIN_PATH
    fi
fi

CMD="scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $IMAGE_PATH/stretch.img.key -P $PORT $BIN_PATH/syz-execprog $BIN_PATH/syz-executor root@localhost:/"

$CMD
echo $CMD > upload-exp.sh
exit $EXITCODE
