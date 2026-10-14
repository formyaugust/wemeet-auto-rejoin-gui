# 腾讯会议自动重进 —— 编译脚本
# 只依赖系统自带的 csc.exe（.NET Framework 4.x），不需要安装任何 SDK。
$ErrorActionPreference = 'Stop'

$dir = $PSScriptRoot
$fw  = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$csc = Join-Path $fw 'csc.exe'
$src = Join-Path $dir 'WeMeetAutoRejoin.cs'
$out = Join-Path $dir '腾讯会议自动重进.exe'

if (-not (Test-Path $csc)) { Write-Host "找不到 csc.exe：$csc" -ForegroundColor Red; exit 1 }
if (-not (Test-Path $src)) { Write-Host "找不到源码：$src" -ForegroundColor Red; exit 1 }

# 先编译成 ASCII 临时名，再改名 —— 避免命令行传中文文件名时的编码问题
$tmp = Join-Path $dir 'WeMeetAutoRejoin.build.exe'
if (Test-Path $tmp) { Remove-Item $tmp -Force }

Write-Host '正在编译…' -ForegroundColor Cyan
& $csc /nologo /target:winexe /platform:x64 /optimize+ "/out:$tmp" `
    /r:"$fw\System.Windows.Forms.dll" /r:"$fw\System.Drawing.dll" $src

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmp)) {
    Write-Host '编译失败，请把上面的错误信息发我。' -ForegroundColor Red
    exit 1
}

Move-Item -LiteralPath $tmp -Destination $out -Force
$kb = [math]::Round((Get-Item -LiteralPath $out).Length / 1KB, 1)
Write-Host "编译成功：$out  ($kb KB)" -ForegroundColor Green
