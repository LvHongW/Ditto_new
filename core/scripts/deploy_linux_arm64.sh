#!/bin/bash

set -ex

echo "running deploy_linux_arm64.sh"

KERNEL_ARCH="arm64"
CROSS_COMPILE_PREFIX="aarch64-linux-gnu-"
EXTRA_HOSTCFLAGS=""
if [ ! -f "/usr/include/dwarf.h" ] && [ -f "/usr/include/libdwarf/dwarf.h" ]; then
  EXTRA_HOSTCFLAGS="-I/usr/include/libdwarf"
fi

ARM64_TOOLCHAIN_BIN=""

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
     [ -x "$ARM64_TOOLCHAIN_BIN/${CROSS_COMPILE_PREFIX}ld" ]; then
    export PATH="$ARM64_TOOLCHAIN_BIN:$PATH"
    echo "[+] Using arm64 toolchain: $tag ($ARM64_TOOLCHAIN_BIN, prefix=$CROSS_COMPILE_PREFIX)"
    return 0
  fi

  return 1
}

function select_arm64_toolchain() {
  # Try bundled toolchains first, then fall back to system.
  pick_arm64_toolchain gcc10 || pick_arm64_toolchain gcc11 || pick_arm64_toolchain gcc12 || pick_arm64_toolchain gcc7 || true

  if [ -z "$ARM64_TOOLCHAIN_BIN" ]; then
    if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
      CROSS_COMPILE_PREFIX="aarch64-linux-gnu-"
      echo "[+] Using system toolchain prefix: $CROSS_COMPILE_PREFIX"
    elif command -v aarch64-none-linux-gnu-gcc >/dev/null 2>&1; then
      CROSS_COMPILE_PREFIX="aarch64-none-linux-gnu-"
      echo "[+] Using system toolchain prefix: $CROSS_COMPILE_PREFIX"
    else
      echo "[!] No arm64 cross toolchain found"
      return 1
    fi
  fi
  return 0
}

function clean_and_jump() {
  git stash --all
  git checkout -f $COMMIT
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-deploy_linux
  exit 1
}

if [ $# -ne 5 ] && [ $# -ne 8 ]; then
  echo "Usage ./deploy_linux_arm64.sh gcc_version fixed linux_path package_path max_compiling_kernel [linux_commit, config_url, mode]"
  exit 1
fi

COMPILER_VERSION=$1
FIXED=$2
LINUX=$3
PROJECT_PATH=$4
MAX_COMPILING_KERNEL=$5
N_CORES=$((`nproc` / $MAX_COMPILING_KERNEL))

select_arm64_toolchain

if [ $# -eq 8 ]; then
  COMMIT=$6
  CONFIG=$7
  MODE=$8
fi

cd $LINUX
cd ..
CASE_PATH=`pwd`
cd linux
if [ $# -eq 5 ]; then
  echo "no more patch"
fi
if [ $# -eq 8 ]; then
  if [ "$FIXED" != "1" ]; then
    git stash
    git clean -fdx -e THIS_KERNEL_IS_BEING_USED > /dev/null
    CURRENT_HEAD=`git rev-parse HEAD`
    if [ "$CURRENT_HEAD" != "$COMMIT" ]; then
      git checkout -f $COMMIT || exit 1
    fi
    cp $CASE_PATH/basic_info/config .config
  else
    git format-patch -1 $COMMIT --stdout > fixed.patch
    patch -p1 -N -i fixed.patch || exit 1
    cp $CASE_PATH/basic_info/config .config
  fi
fi

if [ "$MODE" == "0" ]; then
CONFIGKEYSDISABLE="
CONFIG_BUG_ON_DATA_CORRUPTION
CONFIG_KASAN_INLINE
CONFIG_KCOV
"

CONFIGKEYSENABLE="
CONFIG_KASAN_OUTLINE
"
fi

if [ "$MODE" == "1" ]; then
CONFIGKEYSENABLE="
CONFIG_HAVE_ARCH_KASAN
CONFIG_KASAN
CONFIG_KASAN_OUTLINE
CONFIG_DEBUG_INFO
CONFIG_FRAME_POINTER
CONFIG_UNWINDER_FRAME_POINTER"

CONFIGKEYSDISABLE="
CONFIG_KASAN_INLINE
CONFIG_RANDOMIZE_BASE
CONFIG_SOFTLOCKUP_DETECTOR
CONFIG_LOCKUP_DETECTOR
CONFIG_HARDLOCKUP_DETECTOR
CONFIG_DETECT_HUNG_TASK
CONFIG_WQ_WATCHDOG
CONFIG_PANIC_ON_OOPS
CONFIG_PROVE_LOCKING
CONFIG_DEBUG_RT_MUTEXES
CONFIG_DEBUG_SPINLOCK
CONFIG_DEBUG_MUTEXES
CONFIG_DEBUG_WW_MUTEX_SLOWPATH
CONFIG_DEBUG_RWSEMS
CONFIG_DEBUG_LOCK_ALLOC
CONFIG_DEBUG_ATOMIC_SLEEP
CONFIG_DEBUG_LIST
CONFIG_ARCH_HAS_KCOV
CONFIG_KCOV
CONFIG_KCOV_INSTRUMENT_ALL
"
fi

for key in $CONFIGKEYSDISABLE;
do
  config_disable $key
done

for key in $CONFIGKEYSENABLE;
do
  config_enable $key
done

make ARCH=$KERNEL_ARCH CROSS_COMPILE=$CROSS_COMPILE_PREFIX HOSTCFLAGS="$EXTRA_HOSTCFLAGS" olddefconfig > olddefconfig.log 2>&1 || copy_log_then_exit olddefconfig.log
make ARCH=$KERNEL_ARCH CROSS_COMPILE=$CROSS_COMPILE_PREFIX HOSTCFLAGS="$EXTRA_HOSTCFLAGS" -j$N_CORES > make.log 2>&1 || copy_log_then_exit make.log
exit 0
