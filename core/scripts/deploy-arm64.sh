#!/bin/bash

set -ex

echo "running deploy-arm64.sh"

KERNEL_ARCH="arm64"
CROSS_COMPILE_PREFIX="aarch64-linux-gnu-"
ARM64_TOOLCHAIN_BIN=""
KERNEL_CC_MODE="gcc"
KERNEL_CC_BIN=""
EXTRA_HOSTCFLAGS=""
if [ ! -f "/usr/include/dwarf.h" ] && [ -f "/usr/include/libdwarf/dwarf.h" ]; then
  EXTRA_HOSTCFLAGS="-I/usr/include/libdwarf"
fi

LATEST="9b1f3e6"

function config_disable() {
  key=$1
  sed -i "s/$key=n/# $key is not set/g" .config
  sed -i "s/$key=m/# $key is not set/g" .config
  sed -i "s/$key=y/# $key is not set/g" .config
}

function config_enable() {
  key=$1
  sed -i "s/$key=n/# $key is not set/g" .config
  sed -i "s/$key=m/# $key is not set/g" .config
  sed -i "s/# $key is not set/$key=y/g" .config
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-$COMPILER_VERSION
  exit 1
}

function set_git_config() {
  set +x
  echo "set user.email for git config"
  echo "Input email: "
  read email
  echo "set user.name for git config"
  echo "Input name: "
  read name
  git config --global user.email $email
  git config --global user.name $name
  set -x
}

function build_golang() {
  echo "setup golang environment"
  rm goroot || echo "clean goroot"
  wget https://dl.google.com/go/go1.23.2.linux-amd64.tar.gz
  tar -xf go1.23.2.linux-amd64.tar.gz
  mv go goroot
  if [ ! -d "gopath" ]; then
    mkdir gopath
  fi
  rm go1.23.2.linux-amd64.tar.gz
}

function check_arm64_toolchain() {
  local prefix="$CROSS_COMPILE_PREFIX"
  local missing=0
  local bins=()

  if [ "$KERNEL_CC_MODE" = "clang" ]; then
    bins=(
      "${prefix}objdump"
      "${prefix}ld"
    )
  else
    bins=(
      "${prefix}gcc"
      "${prefix}objdump"
      "${prefix}ld"
    )
  fi
  for b in "${bins[@]}"; do
    if ! command -v "$b" >/dev/null 2>&1; then
      echo "[!] Missing required tool: $b"
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    echo "[!] Arm64 syzkaller target build requires cross toolchain."
    echo "[!] Expected prefix: $prefix"
    echo "[!] Install tools via: ./core/scripts/requirements.sh --setup-arm64-toolchains"
    echo "[!] Or install system toolchain: sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu"
    exit 1
  fi
}

function pick_arm64_toolchain() {
  local tag="$1"
  case "$tag" in
    gcc12)
      ARM64_TOOLCHAIN_BIN="$PROJECT_PATH/tools/aarch64-gcc-12.3/bin"
      CROSS_COMPILE_PREFIX="aarch64-none-linux-gnu-"
      ;;
    gcc11)
      ARM64_TOOLCHAIN_BIN="$PROJECT_PATH/tools/aarch64-gcc-11.3/bin"
      CROSS_COMPILE_PREFIX="aarch64-none-linux-gnu-"
      ;;
    gcc10)
      ARM64_TOOLCHAIN_BIN="$PROJECT_PATH/tools/aarch64-gcc-10.3/bin"
      CROSS_COMPILE_PREFIX="aarch64-none-linux-gnu-"
      ;;
    gcc7)
      ARM64_TOOLCHAIN_BIN="$PROJECT_PATH/tools/linaro-gcc-7.5/bin"
      CROSS_COMPILE_PREFIX="aarch64-linux-gnu-"
      ;;
    *)
      return 1
      ;;
  esac

  if [ -x "$ARM64_TOOLCHAIN_BIN/${CROSS_COMPILE_PREFIX}gcc" ] && \
     [ -x "$ARM64_TOOLCHAIN_BIN/${CROSS_COMPILE_PREFIX}ld" ] && \
     [ -x "$ARM64_TOOLCHAIN_BIN/${CROSS_COMPILE_PREFIX}objdump" ]; then
    export PATH="$ARM64_TOOLCHAIN_BIN:$PATH"
    echo "[+] Using arm64 toolchain: $tag ($ARM64_TOOLCHAIN_BIN, prefix=$CROSS_COMPILE_PREFIX)"
    return 0
  fi

  return 1
}

function clang_major_of() {
  local cc_bin="$1"
  local major
  major=$($cc_bin --version 2>/dev/null | head -n1 | sed -nE 's/.*clang version ([0-9]+)\..*/\1/p')
  echo "$major"
}

function clang_supports_aarch64() {
  local cc_bin="$1"
  local test_c
  local out_o
  test_c=$(mktemp /tmp/ditto-clang-a64-XXXX.c)
  out_o=$(mktemp /tmp/ditto-clang-a64-XXXX.o)
  echo 'int main(void){return 0;}' > "$test_c"
  if "$cc_bin" --target=aarch64-linux-gnu -c "$test_c" -o "$out_o" >/dev/null 2>&1; then
    rm -f "$test_c" "$out_o"
    return 0
  fi
  rm -f "$test_c" "$out_o"
  return 1
}

function pick_best_clang() {
  local required_major="$1"
  local best_bin=""
  local best_major=0
  local candidate
  local major

  # Prefer explicitly versioned clang binaries first, then generic clang.
  for candidate in \
    "$PROJECT_PATH"/tools/clang-*/bin/clang \
    /usr/bin/clang-[0-9]* \
    /usr/local/bin/clang-[0-9]* \
    /usr/bin/clang \
    /usr/local/bin/clang; do
    [ -x "$candidate" ] || continue
    major=$(clang_major_of "$candidate")
    [ -n "$major" ] || continue
    if [ "$major" -gt "$best_major" ]; then
      if clang_supports_aarch64 "$candidate"; then
        best_major="$major"
        best_bin="$candidate"
      fi
    fi
  done

  if [ -z "$best_bin" ]; then
    return 1
  fi

  if [ -n "$required_major" ] && [ "$required_major" -gt 0 ] && [ "$best_major" -lt "$required_major" ]; then
    echo "[!] Best available clang major is $best_major, lower than requested major $required_major"
  fi

  KERNEL_CC_BIN="$best_bin"
  echo "[+] Selected clang: $KERNEL_CC_BIN (major=$best_major)"
  return 0
}

function select_arm64_toolchain_from_case_config() {
  local cfg="$CASE_PATH/basic_info/config"
  local cc_line
  local gcc_major
  local clang_major

  if [ ! -f "$cfg" ]; then
    echo "[!] Missing case config file: $cfg"
    return 1
  fi

  cc_line=$(grep -m1 'CONFIG_CC_VERSION_TEXT=' "$cfg" || true)
  gcc_major=""
  clang_major=""

  if echo "$cc_line" | grep -qi 'clang version'; then
    KERNEL_CC_MODE="clang"
    clang_major=$(echo "$cc_line" | sed -nE 's/.*clang version ([0-9]+)\.[0-9]+\.[0-9]+.*/\1/p')

    if ! pick_best_clang "${clang_major:-0}"; then
      echo "[!] Case config uses clang, but no clang binary found."
      echo "[!] Checked: tools/clang-*/bin/clang and system clang binaries"
      return 1
    fi
    echo "[+] Case config requests CLANG major: ${clang_major:-unknown}"
    echo "[+] Kernel compiler: $KERNEL_CC_BIN"

    if ! clang_supports_aarch64 "$KERNEL_CC_BIN"; then
      echo "[!] Selected clang cannot target aarch64: $KERNEL_CC_BIN"
      echo "[!] Fall back to GCC toolchain for this case."
      KERNEL_CC_MODE="gcc"
      KERNEL_CC_BIN=""
    fi

    if [ "$KERNEL_CC_MODE" = "clang" ]; then
      # In clang mode, prefer aarch64-linux-gnu- to avoid unknown vendor triplets.
      if command -v aarch64-linux-gnu-ld >/dev/null 2>&1 && command -v aarch64-linux-gnu-objdump >/dev/null 2>&1; then
        CROSS_COMPILE_PREFIX="aarch64-linux-gnu-"
        echo "[+] Clang mode cross prefix: $CROSS_COMPILE_PREFIX"
      else
        # Keep a GNU cross toolchain for linker/binutils.
        pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc12 || pick_arm64_toolchain gcc7 || true
        if [ -z "$ARM64_TOOLCHAIN_BIN" ]; then
          if command -v aarch64-none-linux-gnu-ld >/dev/null 2>&1 && command -v aarch64-none-linux-gnu-objdump >/dev/null 2>&1; then
            CROSS_COMPILE_PREFIX="aarch64-none-linux-gnu-"
          else
            echo "[!] No usable arm64 GNU toolchain found for clang cross build"
            return 1
          fi
        fi
      fi
    fi
  elif [ -n "$cc_line" ]; then
    gcc_major=$(echo "$cc_line" | sed -nE 's/.*gcc[^0-9]*([0-9]+)\.[0-9]+\.[0-9]+.*/\1/p')
  fi

  if [ "$KERNEL_CC_MODE" = "gcc" ] && [ -n "$gcc_major" ]; then
    echo "[+] Case config requests GCC major: $gcc_major"
    case "$gcc_major" in
      12)
        pick_arm64_toolchain gcc12 || pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc7 || true
        ;;
      11)
        pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc12 || pick_arm64_toolchain gcc7 || true
        ;;
      10)
        pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc12 || pick_arm64_toolchain gcc7 || true
        ;;
      9|8)
        pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc7 || pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc12 || true
        ;;
      7)
        pick_arm64_toolchain gcc7 || pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc12 || true
        ;;
      *)
        pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc12 || pick_arm64_toolchain gcc7 || true
        ;;
    esac
  elif [ "$KERNEL_CC_MODE" = "gcc" ]; then
    echo "[!] Cannot parse GCC version from case config, use best available toolchain"
    pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc12 || pick_arm64_toolchain gcc7 || true
  fi

  # Fallback to system toolchains in PATH if no local toolchain is selected.
  if [ -z "$ARM64_TOOLCHAIN_BIN" ]; then
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
      CROSS_COMPILE_PREFIX="aarch64-linux-gnu-"
      echo "[+] Fallback to system toolchain prefix: $CROSS_COMPILE_PREFIX"
    elif command -v aarch64-none-linux-gnu-gcc >/dev/null 2>&1; then
      CROSS_COMPILE_PREFIX="aarch64-none-linux-gnu-"
      echo "[+] Fallback to system toolchain prefix: $CROSS_COMPILE_PREFIX"
    else
      echo "[!] No usable arm64 toolchain found in tools/ or system PATH"
      echo "[!] Run: ./core/scripts/requirements.sh --setup-arm64-toolchains"
      return 1
    fi
  fi

  return 0
}

if [ $# -ne 13 ]; then
  echo "Usage ./deploy-arm64.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase index catalog image arch gcc_version max_compiling_kernel save_linux_folder"
  exit 1
fi

HASH=$2
COMMIT=$3
SYZKALLER=$4
CONFIG=$5
TESTCASE=$6
INDEX=$7
CATALOG=$8
IMAGE=$9
ARCH=${10}
COMPILER_VERSION=${11}
MAX_COMPILING_KERNEL=${12}
save_linux_folder=${13}
PROJECT_PATH="$(pwd)"
PKG_NAME="core"
CASE_PATH=$PROJECT_PATH/work/$CATALOG/$HASH
PATCHES_PATH=$PROJECT_PATH/$PKG_NAME/patches
LLVM_PATCHED_PATH=$PROJECT_PATH/tools/llvm/build

echo "Compiler: "$COMPILER_VERSION | grep gcc && \
COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/gcc || \
COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/clang
N_CORES=$((`nproc` / $MAX_COMPILING_KERNEL))

if [ ! -d "$save_linux_folder/$1-$INDEX" ]; then
  echo "No linux repositories detected"
  exit 1
fi

cd $save_linux_folder/$1-$INDEX
if [ ! -d ".git" ]; then
  echo "This linux repo is not clone by git."
  exit 1
fi

cd ..

select_arm64_toolchain_from_case_config
check_arm64_toolchain

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
echo "[+] Go tmp dir: $TMPDIR"
echo "[+] Go cache dir: $GOCACHE"
echo "[+] Downloading golang"
go version || build_golang

cd $CASE_PATH || exit 1
if [ ! -d ".stamp" ]; then
  mkdir .stamp
fi

if [ ! -d "compiler" ]; then
  mkdir compiler
fi
cd compiler
if [ ! -L "$CASE_PATH/compiler/compiler" ]; then
  ln -s $COMPILER ./compiler
fi

echo "[+] Building syzkaller"
if [ ! -f "$CASE_PATH/.stamp/BUILD_SYZKALLER" ]; then
  # Clean arm image build artifacts that may contain special device files.
  # If left in syzkaller source tree, plain `cp -r` fails with EPERM.
  for artifact in stretch-arm64 wheezy-arm64 trixie-arm64; do
    if [ -e "$PROJECT_PATH/tools/gopath/src/github.com/google/syzkaller/$artifact" ]; then
      sudo rm -rf "$PROJECT_PATH/tools/gopath/src/github.com/google/syzkaller/$artifact"
    fi
  done
  if [ -d "$GOPATH/src/github.com/google/syzkaller" ]; then
    rm -rf $GOPATH/src/github.com/google/syzkaller
  fi
  mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
  cd $GOPATH/src/github.com/google/
  cp -r $PROJECT_PATH/tools/gopath/src/github.com/google/syzkaller ./
  cd $GOPATH/src/github.com/google/syzkaller || exit 1
  git stash --all || set_git_config
  git checkout -f 9b1f3e665308ee2ddd5b3f35a078219b5c509cdb
  make clean > syzkaller_clean.log 2>&1 || true
  patch -p1 -i $PATCHES_PATH/syzkaller-9b1f3e6-ditto.patch

  make TARGETARCH=$ARCH TARGETVMARCH=arm64 > syzkaller_make.log 2>&1 || copy_log_then_exit syzkaller_make.log
  if [ ! -d "workdir" ]; then
    mkdir workdir
  fi

  cp $CASE_PATH/basic_info/syz_repro $GOPATH/src/github.com/google/syzkaller/workdir/testcase-$HASH
  touch $CASE_PATH/.stamp/BUILD_SYZKALLER
fi

cd $CASE_PATH || exit 1
echo "[+] Copy image"
if [ ! -d "$CASE_PATH/img" ]; then
  mkdir -p $CASE_PATH/img
fi
cd img
# Arm64 kernel must pair with arm64 rootfs. Accept either "stretch-arm64"
# directly or auto-upgrade a base image name like "stretch" to "stretch-arm64".
ARM_IMAGE="$IMAGE"
if [[ "$ARM_IMAGE" != *-arm64 ]]; then
  if [ -f "$PROJECT_PATH/tools/img/${ARM_IMAGE}-arm64.img" ] && [ -f "$PROJECT_PATH/tools/img/${ARM_IMAGE}-arm64.img.key" ]; then
    ARM_IMAGE="${ARM_IMAGE}-arm64"
    echo "[+] Use arm64 image: $ARM_IMAGE"
  else
    echo "[!] Invalid arm64 image input: $IMAGE"
    echo "[!] Missing $PROJECT_PATH/tools/img/${ARM_IMAGE}-arm64.img(.key)"
    echo "[!] Existing stretch/wheezy images are x86 rootfs and cannot boot arm64 userland."
    echo "[!] Please prepare an arm64 rootfs image and key pair as:"
    echo "[!]   tools/img/${ARM_IMAGE}-arm64.img"
    echo "[!]   tools/img/${ARM_IMAGE}-arm64.img.key"
    echo "[!] You can generate them with:"
    echo "[!]   core/scripts/requirements.sh --build-arm64-image ${ARM_IMAGE}"
    exit 1
  fi
fi
if [ ! -L "$CASE_PATH/img/stretch.img" ]; then
  ln -s $PROJECT_PATH/tools/img/$ARM_IMAGE.img ./stretch.img
fi
if [ ! -L "$CASE_PATH/img/stretch.img.key" ]; then
  ln -s $PROJECT_PATH/tools/img/$ARM_IMAGE.img.key ./stretch.img.key
fi
# syzkaller checks ssh key permission strictly and expects 0600.
chmod 600 "$PROJECT_PATH/tools/img/$ARM_IMAGE.img.key" || true
chmod 600 "$CASE_PATH/img/stretch.img.key" || true
cd ..

echo "[+] Building kernel"
OLD_INDEX=`ls -l linux | cut -d'-' -f 3`
if [ "$OLD_INDEX" != "$INDEX" ]; then
  rm -rf "./linux" || echo "No linux repo"
  ln -s $save_linux_folder/$1-$INDEX ./linux
  if [ -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
      rm $CASE_PATH/.stamp/BUILD_KERNEL
  fi
fi
if [ ! -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
  cd linux
  git stash || echo "it's ok"
  make clean > /dev/null || echo "it's ok"
  git clean -fdx -e THIS_KERNEL_IS_BEING_USED > /dev/null || echo "it's ok"
  git checkout -f $COMMIT || exit 1
  cp $CASE_PATH/basic_info/config .config

  CONFIGKEYSENABLE="
    CONFIG_HAVE_ARCH_KASAN
    CONFIG_KASAN
    CONFIG_KASAN_OUTLINE
    CONFIG_DEBUG_INFO
    CONFIG_FRAME_POINTER
    CONFIG_UNWINDER_FRAME_POINTER
    CONFIG_KCOV
    CONFIG_KCOV_INSTRUMENT_ALL
    CONFIG_KCOV_ENABLE_COMPARISONS
    CONFIG_DEBUG_FS
    CONFIG_DEBUG_KMEMLEAK
    CONFIG_KALLSYMS
    CONFIG_KALLSYMS_ALL"

  CONFIGKEYSDISABLE="
    CONFIG_BUG_ON_DATA_CORRUPTION
    CONFIG_KASAN_INLINE
    CONFIG_RANDOMIZE_BASE
    CONFIG_PANIC_ON_OOPS
    CONFIG_BOOTPARAM_SOFTLOCKUP_PANIC
    CONFIG_BOOTPARAM_HARDLOCKUP_PANIC
    CONFIG_BOOTPARAM_HUNG_TASK_PANIC"

  for key in $CONFIGKEYSDISABLE;
  do
    config_disable $key
  done

  for key in $CONFIGKEYSENABLE;
  do
    config_enable $key
  done

  if [ "$KERNEL_CC_MODE" = "clang" ]; then
    local_cc_major=$(clang_major_of "$KERNEL_CC_BIN")
    if [ -z "$local_cc_major" ] || [ "$local_cc_major" -lt 13 ]; then
      echo "[!] Clang is too old for this kernel: $KERNEL_CC_BIN (major=${local_cc_major:-unknown})"
      echo "[!] Kernel requires clang >= 13. Please install newer clang (e.g. clang-16/clang-17) and retry."
      exit 1
    fi

    make ARCH=$KERNEL_ARCH CROSS_COMPILE=$CROSS_COMPILE_PREFIX HOSTCFLAGS="$EXTRA_HOSTCFLAGS" CC="$KERNEL_CC_BIN" olddefconfig > olddefconfig.log 2>&1 || copy_log_then_exit olddefconfig.log
  else
    make ARCH=$KERNEL_ARCH CROSS_COMPILE=$CROSS_COMPILE_PREFIX HOSTCFLAGS="$EXTRA_HOSTCFLAGS" olddefconfig > olddefconfig.log 2>&1 || copy_log_then_exit olddefconfig.log
  fi

  if ! grep -q '^CONFIG_KCOV=y' .config; then
    echo "[!] CONFIG_KCOV is not enabled after olddefconfig"
    grep -E '^CONFIG_CC_IS_CLANG=|^CONFIG_CC_IS_GCC=|^CONFIG_KCOV=' .config || true
    exit 1
  fi

  if [ "$KERNEL_CC_MODE" = "clang" ]; then
    make ARCH=$KERNEL_ARCH CROSS_COMPILE=$CROSS_COMPILE_PREFIX HOSTCFLAGS="$EXTRA_HOSTCFLAGS" CC="$KERNEL_CC_BIN" -j$N_CORES > make.log 2>&1 || copy_log_then_exit make.log
  else
    make ARCH=$KERNEL_ARCH CROSS_COMPILE=$CROSS_COMPILE_PREFIX HOSTCFLAGS="$EXTRA_HOSTCFLAGS" -j$N_CORES > make.log 2>&1 || copy_log_then_exit make.log
  fi
  rm $CASE_PATH/config || echo "It's ok"
  cp .config $CASE_PATH/config
  touch $CASE_PATH/.stamp/BUILD_KERNEL
fi

exit 0
