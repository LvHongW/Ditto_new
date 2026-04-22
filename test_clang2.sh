PROJECT_PATH=/disk0/jiang_pro/Ditto_new
function clang_major_of() {
  local bin="$1"
  "$bin" --version 2>/dev/null | head -n1 | grep -o 'clang version [0-9]\+' | awk '{print $3}'
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
  echo "Best bin: $best_bin, major: $best_major"
}
pick_best_clang 13
