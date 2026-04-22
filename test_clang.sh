PROJECT_PATH=/disk0/jiang_pro/Ditto_new
function clang_major_of() {
  local bin="$1"
  "$bin" --version 2>/dev/null | head -n1 | grep -o 'clang version [0-9]\+' | awk '{print $3}'
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
      best_major="$major"
      best_bin="$candidate"
    fi
  done
  echo "Best bin: $best_bin, major: $best_major"
}
pick_best_clang 13
