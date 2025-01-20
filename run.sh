#!/bin/bash

# 运行 helper.py 脚本
# 使用 sources.yaml 作为输入文件
# 使用 output.yaml 作为输出文件
# 使用 normal 作为日志详细程度
pip3 install requests pyyaml
python3 helper.py sources.yaml output.yaml verbose
echo "Clash 配置文件已生成：output.yaml"