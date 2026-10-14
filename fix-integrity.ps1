# 修复「低完整性标签」问题
#
# 现象：程序能识别窗口、能切前台，但点击和键盘输入完全没反应。
# 原因：exe 文件或所在文件夹被打上了 Low Mandatory Level 标签
#       （凡是由受限/沙箱进程创建的文件都会自动带上这个标签）。
#       Windows 的 UIPI 机制禁止低完整性进程向普通权限的腾讯会议注入输入。
#
# 本脚本尝试把标签提升为 Medium。若失败，请按提示改用「复制文件夹」的办法。

$ErrorActionPreference = 'Continue'
$dir = $PSScriptRoot
$exe = Join-Path $dir '腾讯会议自动重进.exe'

function Get-ExeLabel {
    param([string]$Path)
    $out = icacls "$Path" 2>&1 | Out-String
    if ($out -match 'Low Mandatory') { return 'Low' }
    if ($out -match 'Medium Mandatory') { return 'Medium' }
    if ($out -match 'High Mandatory') { return 'High' }
    return '未知'
}

# 本进程自己的完整性级别
$me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([System.Security.Principal.WindowsPrincipal]$me).IsInRole(
    [System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host '=============================================='
Write-Host ' 完整性标签修复'
Write-Host '=============================================='
Write-Host "目标目录 : $dir"
Write-Host "当前身份 : $($me.Name)  $(if ($isAdmin) { '(管理员)' } else { '(普通用户)' })"
Write-Host ''

$before = Get-ExeLabel -Path $exe
Write-Host "exe 当前标签 : $before"
Write-Host ''

if ($before -eq 'Medium' -or $before -eq 'High') {
    Write-Host '标签正常，不需要修复。' -ForegroundColor Green
    Write-Host ''
    Read-Host '按回车退出'
    exit 0
}

Write-Host '正在尝试把目录和文件标签提升为 Medium …' -ForegroundColor Cyan
icacls "$dir" /setintegritylevel '(OI)(CI)Medium' /T /C 2>&1 | Out-Null
icacls "$dir" /setintegritylevel Medium /T /C 2>&1 | Out-Null

$after = Get-ExeLabel -Path $exe
Write-Host "exe 修复后标签 : $after"
Write-Host ''

if ($after -eq 'Medium' -or $after -eq 'High') {
    Write-Host '修复成功！现在可以正常运行 exe 了。' -ForegroundColor Green
    Write-Host ''
    Read-Host '按回车退出'
    exit 0
}

Write-Host '自动修复失败（当前权限不足以提升标签）。' -ForegroundColor Red
Write-Host ''
Write-Host '请改用下面的办法，一定能解决：' -ForegroundColor Yellow
Write-Host ''
Write-Host '  1. 在【桌面】或【D 盘】新建一个文件夹，例如  D:\腾讯会议自动重进'
Write-Host '  2. 把本文件夹里的 5 个文件【复制】过去'
Write-Host '     （用资源管理器复制粘贴，不要用移动）'
Write-Host '  3. 从新文件夹里运行 exe'
Write-Host ''
Write-Host '  原理：由你自己的普通权限进程复制出来的文件，标签会恢复正常。'
Write-Host '  复制完成后，旧文件夹可以直接删掉。'
Write-Host ''
Read-Host '按回车退出'
