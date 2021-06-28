@echo off
echo Scan and repair all NLS files in %systemroot%\system32 directory
pause
for /f %%g in ('dir /b /s %systemroot%\system32\*.nls') do (
    echo Scan file %%g
    sfc /scanfile=%%g
    echo.
)
pause
