@echo off
chcp 65001
set "PYTHONIOENCODING=utf-8"
setlocal
REM Keep every temp write inside this folder (nothing lands on C:).
if not exist "%~dp0.py-tmp" mkdir "%~dp0.py-tmp"
set "TMP=%~dp0.py-tmp"
set "TEMP=%~dp0.py-tmp"
set "PYTHONNOUSERSITE=1"
REM 运行Python脚本生成配置文件（使用项目内嵌Python）
python\python.exe helper.py sources.yaml output.yaml
if errorlevel 1 (pause & goto :eof)
echo Clash配置文件已生成：output.yaml

REM 配置Git并提交更改
REM git config --global core.quotepath false
REM git config --global i18n.commitencoding utf-8
REM git config --global i18n.logoutputencoding utf-8
REM git config --global gui.encoding utf-8
REM git config --global user.name "EricLeeaaaaa"
REM git config --global user.email "ericleeaaaaa@github.com"
git add output.yaml
git commit -m "更新 Clash 配置文件"
git push

echo 所有操作已完成！
pause
