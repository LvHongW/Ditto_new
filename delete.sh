#!/bin/bash

# 删除指定路径下所有以'aarch'开头的符号链接
# 用法: ./remove_aarch_links.sh "your/path/pattern"

# 获取用户输入的路径模式
TARGET_PATTERN="$1"

# 如果没有提供参数，提示使用方法
if [ -z "$TARGET_PATTERN" ]; then
    echo "使用方法: $0 <路径模式>"
    echo "示例: $0 \"tools/*/bin\""
    echo "示例: $0 \"/home/user/project/tools\""
    exit 1
fi

echo "在以下路径中搜索aarch*符号链接: $TARGET_PATTERN"
echo "------------------------"

# 统计将要删除的符号链接
count=0
link_list=""

# 收集符号链接列表
for path in $TARGET_PATTERN; do
    if [ -e "$path" ]; then
        echo "检查: $path"
        for link in $(find "$path" -name "aarch*" -type l 2>/dev/null); do
            target=$(readlink -f "$link" 2>/dev/null || readlink "$link" 2>/dev/null)
            echo "  $link -> $target"
            link_list="$link_list\n$link"
            ((count++))
        done
    fi
done

echo "------------------------"
echo "找到 $count 个以'aarch'开头的符号链接"

if [ $count -eq 0 ]; then
    echo "没有找到要删除的符号链接"
    exit 0
fi

# 确认删除
read -p "确认删除这些符号链接？(y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # 执行删除
    for path in $TARGET_PATTERN; do
        if [ -e "$path" ]; then
            find "$path" -name "aarch*" -type l -exec rm -v {} \;
        fi
    done
    echo "已删除 $count 个符号链接"
else
    echo "操作已取消"
fi