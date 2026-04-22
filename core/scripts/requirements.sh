#!/bin/bash

set -euo pipefail

download_arm64_toolchain() {
  local name="$1"
  local url="$2"
  local target_dir="$3"
  local extract_glob="$4"
  local archive

  if [ -d "$target_dir/bin" ]; then
    echo "[+] Arm64 toolchain exists: $name"
    return 0
  fi

  archive="${name}.tar.xz"
  echo "[+] Download arm64 toolchain: $name"
  wget -q --show-progress -O "$archive" "$url"
  tar -xf "$archive"
  rm -f "$archive"

  local extracted
  extracted=$(ls -d $extract_glob 2>/dev/null | head -n1 || true)
  if [ -z "$extracted" ]; then
    echo "[!] Failed to locate extracted directory for $name"
    exit 1
  fi

  rm -rf "$target_dir"
  mv "$extracted" "$target_dir"
}

setup_arm64_toolchains() {
  local tools_path="$1"

  echo "[+] Setup arm64 cross toolchains"
  cd "$tools_path"

  download_arm64_toolchain \
    "aarch64-gcc-12.3" \
    "https://developer.arm.com/-/media/Files/downloads/gnu/12.3.rel1/binrel/arm-gnu-toolchain-12.3.rel1-x86_64-aarch64-none-linux-gnu.tar.xz" \
    "$tools_path/aarch64-gcc-12.3" \
    "arm-gnu-toolchain-12.3.rel1-x86_64-aarch64-none-linux-gnu"

  download_arm64_toolchain \
    "aarch64-gcc-11.3" \
    "https://developer.arm.com/-/media/Files/downloads/gnu/11.3.rel1/binrel/arm-gnu-toolchain-11.3.rel1-x86_64-aarch64-none-linux-gnu.tar.xz" \
    "$tools_path/aarch64-gcc-11.3" \
    "arm-gnu-toolchain-11.3.rel1-x86_64-aarch64-none-linux-gnu"

  download_arm64_toolchain \
    "aarch64-gcc-10.3" \
    "https://developer.arm.com/-/media/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu.tar.xz" \
    "$tools_path/aarch64-gcc-10.3" \
    "gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu"

  download_arm64_toolchain \
    "linaro-gcc-7.5" \
    "https://releases.linaro.org/components/toolchain/binaries/7.5-2019.12/aarch64-linux-gnu/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu.tar.xz" \
    "$tools_path/linaro-gcc-7.5" \
    "gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu"
}

build_arm64_image() {
  local distro="$1"
  local feature="$2"
  local project_path
  local syz_path
  local img_dir
  local out_prefix
  local removed_keyring
  local fallback_keyring
  local stretch_archive_key
  local key_tmp

  project_path="$(pwd)"
  syz_path="$project_path/tools/gopath/src/github.com/google/syzkaller"
  img_dir="$project_path/tools/img"
  out_prefix="${distro}-arm64"
  removed_keyring="/usr/share/keyrings/debian-archive-removed-keys.gpg"
  fallback_keyring="/usr/share/keyrings/debian-archive-keyring.gpg"
  stretch_archive_key="EF0F382A1A7B6500"

  if ! command -v qemu-aarch64-static >/dev/null 2>&1; then
    echo "[!] Missing qemu-aarch64-static"
    echo "[!] Install: sudo apt-get install -y qemu-user-static binfmt-support"
    exit 1
  fi

  if [ ! -r /proc/sys/fs/binfmt_misc/qemu-aarch64 ]; then
    echo "[!] Missing binfmt entry /proc/sys/fs/binfmt_misc/qemu-aarch64"
    echo "[!] Try: sudo update-binfmts --enable qemu-aarch64"
    exit 1
  fi

  if [ ! -d "$syz_path" ]; then
    echo "[+] Setup syzkaller source for image creation"
    mkdir -p "$project_path/tools/gopath/src/github.com/google"
    cd "$project_path/tools/gopath/src/github.com/google"
    git clone https://github.com/google/syzkaller.git
    cd "$project_path"
  fi

  # syzkaller create-image.sh may fallback to archive.debian.org for EOL distros
  # and require debian-archive-removed-keys.gpg. On some hosts this file is
  # missing or outdated and does not include stretch archive signing key.
  if [ ! -f "$removed_keyring" ]; then
    if [ -f "$fallback_keyring" ]; then
      echo "[+] Missing removed-keys keyring, creating compatibility copy"
      sudo cp "$fallback_keyring" "$removed_keyring"
    else
      echo "[!] Missing keyrings:"
      echo "[!]   $removed_keyring"
      echo "[!]   $fallback_keyring"
      echo "[!] Install: sudo apt-get install -y debian-archive-keyring"
      exit 1
    fi
  fi

  # Ensure stretch archive key is present in the keyring used by debootstrap.
  if ! gpg --no-default-keyring --keyring "$removed_keyring" --list-keys "$stretch_archive_key" >/dev/null 2>&1; then
    echo "[+] Key $stretch_archive_key not found in $removed_keyring"

    if ! gpg --list-keys "$stretch_archive_key" >/dev/null 2>&1; then
      echo "[+] Importing key $stretch_archive_key into user keyring"
      gpg --keyserver keyserver.ubuntu.com --recv-keys "$stretch_archive_key"
    fi

    key_tmp="$(mktemp)"
    gpg --export "$stretch_archive_key" > "$key_tmp"
    sudo gpg --batch --yes --no-default-keyring --keyring "$removed_keyring" --import "$key_tmp"
    rm -f "$key_tmp"
  fi

  mkdir -p "$img_dir"
  cd "$syz_path"

  echo "[+] Building $out_prefix image via syzkaller tools/create-image.sh"
  rm -f "$out_prefix.img" "$out_prefix.id_rsa" "$out_prefix.id_rsa.pub"
  ./tools/create-image.sh -a aarch64 -d "$distro" -f "$feature" -o "$out_prefix"

  if [ ! -f "$out_prefix.img" ] || [ ! -f "$out_prefix.id_rsa" ]; then
    echo "[!] Image build did not produce expected files"
    exit 1
  fi

  cp -f "$out_prefix.img" "$img_dir/$out_prefix.img"
  cp -f "$out_prefix.id_rsa" "$img_dir/$out_prefix.img.key"
  chmod 600 "$img_dir/$out_prefix.img.key"

  # Avoid polluting syzkaller source tree with rootfs dir containing /dev nodes.
  # These special files break later `cp -r` in deploy scripts.
  sudo rm -rf "$out_prefix"
  rm -f "$out_prefix.img" "$out_prefix.id_rsa" "$out_prefix.id_rsa.pub"

  echo "[+] Generated: $img_dir/$out_prefix.img"
  echo "[+] Generated: $img_dir/$out_prefix.img.key"
}

if [ "${1:-}" = "--build-arm64-image" ]; then
  DISTRO="${2:-stretch}"
  FEATURE="${3:-minimal}"
  case "$DISTRO" in
    stretch|wheezy|trixie) ;;
    *)
      echo "Usage: ./core/scripts/requirements.sh --build-arm64-image <stretch|wheezy|trixie> [minimal|full]"
      exit 1
      ;;
  esac
  case "$FEATURE" in
    minimal|full) ;;
    *)
      echo "Usage: ./core/scripts/requirements.sh --build-arm64-image <stretch|wheezy|trixie> [minimal|full]"
      exit 1
      ;;
  esac
  build_arm64_image "$DISTRO" "$FEATURE"
  exit 0
fi

if [ "${1:-}" = "--setup-arm64-toolchains" ]; then
  setup_arm64_toolchains "$(pwd)/tools"
  touch "$(pwd)/tools/.stamp/SETUP_ARM64_TOOLCHAINS"
  exit 0
fi

if [ ! -f "$(pwd)/tools/.stamp/ENV_SETUP" ]; then
  sudo apt-get -y install gdb curl git wget qemu-system-x86 qemu-system-arm qemu-user-static binfmt-support debootstrap flex bison libssl-dev libelf-dev libdw-dev libdwarf-dev locales cmake libxml2-dev libz3-dev bc libncurses5 gcc-multilib g++-multilib dwarves gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu
fi

if [ ! -d "work/completed" ]; then
  mkdir -p work/completed
fi

if [ ! -d "work/incomplete" ]; then
  mkdir -p work/incomplete
fi

TOOLS_PATH="$(pwd)/tools"
CORE_PATH="$(pwd)/core"
PATCHES_PATH=$CORE_PATH/patches
if [ ! -d "$TOOLS_PATH/.stamp" ]; then
  mkdir -p $TOOLS_PATH/.stamp
fi

echo "[+] Setup arm64 toolchains"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_ARM64_TOOLCHAINS" ]; then
  setup_arm64_toolchains "$TOOLS_PATH"
  touch "$TOOLS_PATH/.stamp/SETUP_ARM64_TOOLCHAINS"
fi

echo "[+] Building image"
cd $TOOLS_PATH
if [ ! -f "$TOOLS_PATH/.stamp/BUILD_IMAGE" ]; then
  if [ ! -d "img" ]; then
    mkdir img
  fi
  cd img
  if [ ! -f "stretch.img" ]; then
    wget https://storage.googleapis.com/syzkaller/stretch.img > /dev/null
    wget https://storage.googleapis.com/syzkaller/stretch.img.key > /dev/null
    chmod 600 stretch.img.key
    wget https://storage.googleapis.com/syzkaller/wheezy.img > /dev/null
    wget https://storage.googleapis.com/syzkaller/wheezy.img.key > /dev/null
    chmod 600 wheezy.img.key
    touch $TOOLS_PATH/.stamp/BUILD_IMAGE
  fi
  cd ..
fi

echo "[+] Building gcc and clang"
if [ ! -f "$TOOLS_PATH/.stamp/BUILD_GCC_CLANG" ]; then
  wget https://storage.googleapis.com/syzkaller/gcc-7.tar.gz > /dev/null
  tar xzf gcc-7.tar.gz
  mv gcc gcc-7
  rm gcc-7.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180301.tar.gz > /dev/null
  tar xzf gcc-8.0.1-20180301.tar.gz
  mv gcc gcc-8.0.1-20180301
  rm gcc-8.0.1-20180301.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180412.tar.gz > /dev/null
  tar xzf gcc-8.0.1-20180412.tar.gz
  mv gcc gcc-8.0.1-20180412
  rm gcc-8.0.1-20180412.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-9.0.0-20181231.tar.gz > /dev/null
  tar xzf gcc-9.0.0-20181231.tar.gz
  mv gcc gcc-9.0.0-20181231
  rm gcc-9.0.0-20181231.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-10.1.0-syz.tar.xz > /dev/null
  tar xf gcc-10.1.0-syz.tar.xz
  mv gcc-10 gcc-10.1.0-20200507
  rm gcc-10.1.0-syz.tar.xz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-329060.tar.gz > /dev/null
  tar xzf clang-kmsan-329060.tar.gz
  mv clang-kmsan-329060 clang-7-329060
  rm clang-kmsan-329060.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-334104.tar.gz > /dev/null
  tar xzf clang-kmsan-334104.tar.gz
  mv clang-kmsan-334104 clang-7-334104
  rm clang-kmsan-334104.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-kmsan-343298.tar.gz > /dev/null
  tar xzf clang-kmsan-343298.tar.gz
  mv clang-kmsan-343298 clang-8-343298
  rm clang-kmsan-343298.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang_install_c2443155.tar.gz > /dev/null
  tar xzf clang_install_c2443155.tar.gz
  mv clang_install_c2443155 clang-10-c2443155
  rm clang_install_c2443155.tar.gz

  wget https://storage.googleapis.com/syzkaller/clang-11-prerelease-ca2dcbd030e.tar.xz > /dev/null
  tar xf clang-11-prerelease-ca2dcbd030e.tar.xz
  mv clang clang-11-ca2dcbd030e
  rm clang-11-prerelease-ca2dcbd030e.tar.xz

  touch $TOOLS_PATH/.stamp/BUILD_GCC_CLANG
fi

echo "[+] Download pwndbg"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_PWNDBG" ]; then
  git clone https://github.com/plummm/pwndbg_linux_kernel.git pwndbg
  cd pwndbg
  ./setup.sh
  locale-gen
  sudo sed -i "s/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/g" /etc/locale.gen
  locale-gen

  touch $TOOLS_PATH/.stamp/SETUP_PWNDBG
  cd ..
fi

echo "[+] Setup golang environment"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_GOLANG" ]; then
  wget https://dl.google.com/go/go1.23.2.linux-amd64.tar.gz
  tar -xf go1.23.2.linux-amd64.tar.gz
  mv go goroot
  GOPATH=`pwd`/gopath
  if [ ! -d "gopath" ]; then
    mkdir gopath
  fi
  rm go1.23.2.linux-amd64.tar.gz
  touch $TOOLS_PATH/.stamp/SETUP_GOLANG
fi

echo "[+] Setup syzkaller"
if [ ! -f "$TOOLS_PATH/.stamp/SETUP_SYZKALLER" ]; then
  mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
  cd $GOPATH/src/github.com/google/
  rm -rf syzkaller || echo "syzkaller does not exist"
  git clone https://github.com/google/syzkaller.git
  touch $TOOLS_PATH/.stamp/SETUP_SYZKALLER
fi

touch $TOOLS_PATH/.stamp/ENV_SETUP

if [ -f "/usr/lib/x86_64-linux-gnu/libmpfr.so.6" ] && [ ! -f "/usr/lib/x86_64-linux-gnu/libmpfr.so.4" ]; then
  sudo ln -s /usr/lib/x86_64-linux-gnu/libmpfr.so.6 /usr/lib/x86_64-linux-gnu/libmpfr.so.4
fi

echo "[+] Clean unfinished jobs"
rm linux-*/.git/index.lock || echo "Removing index.lock"
rm linux-*/THIS_KERNEL_IS_BEING_USED || echo "All set"

exit 0
