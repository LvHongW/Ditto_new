#!/bin/bash

set -ex

if [ $# -ne 3 ]; then
  echo "Usage ./run-vm-arm64.sh image_path linux_path ssh_port"
  exit 1
fi

IMAGE=$1
LINUX=$2
PORT=$3

qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a57 \
  -m 2G \
  -smp 2 \
  -netdev user,id=net0,hostfwd=tcp::$PORT-:22 \
  -device virtio-net-device,netdev=net0 \
  -display none -serial stdio -no-reboot \
  -drive if=none,file=$IMAGE,format=raw,id=hd0 \
  -device virtio-blk-device,drive=hd0 \
  -kernel $LINUX/arch/arm64/boot/Image \
  -append "console=ttyAMA0 root=/dev/vda printk.synchronous=1"
