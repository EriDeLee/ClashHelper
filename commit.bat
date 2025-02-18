@echo off
chcp 65001

REM 运行Python脚本生成配置文件
python helper.py sources.yaml output.yaml
echo Clash配置文件已生成：output.yaml

REM 配置Git并提交更改
git config --global core.quotepath false
git config --global i18n.commitencoding utf-8
git config --global i18n.logoutputencoding utf-8
git config --global gui.encoding utf-8
git config --global user.name "EricLeeaaaaa"
git config --global user.email "ericleeaaaaa@github.com"
git add output.yaml
git commit -m "更新 Clash 配置文件"
git push

echo 所有操作已完成！
pause