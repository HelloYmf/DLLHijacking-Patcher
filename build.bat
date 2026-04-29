@echo off
setlocal enabledelayedexpansion

rem ============================================================
rem  build.bat  [arch]  [config]
rem
rem  arch   : x86 | x64 | all         (default: all)
rem  config : Debug | Release | all    (default: Debug)
rem
rem  Examples:
rem    build.bat                  -> all archs, Debug
rem    build.bat x64 Release      -> x64 Release
rem    build.bat x86              -> x86 Debug
rem    build.bat all Release      -> x86+x64, Release
rem    build.bat all all          -> every combination
rem ============================================================

set ARCH=%~1
set CONFIG=%~2
if /i .%ARCH%.==..   set ARCH=all
if /i .%CONFIG%.==.. set CONFIG=Debug

rem -- CMake path (VS2026) --------------------------------------------------
set CMAKE_EXE=D:\software\VisualStudio2026\Product\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe
echo Using cmake: %CMAKE_EXE%

rem -- Expand "all" --------------------------------------------------------
if /i .%ARCH%.==.all.   ( set _ARCHS=x86 x64     ) else ( set _ARCHS=%ARCH%  )
if /i .%CONFIG%.==.all. ( set _CFGS=Debug Release ) else ( set _CFGS=%CONFIG% )

for %%A in (%_ARCHS%) do (
    for %%C in (%_CFGS%) do (
        if /i .%%A.==.x86. (
            call :one x86 Win32 %%C
        ) else if /i .%%A.==.x64. (
            call :one x64 x64 %%C
        ) else (
            echo ERROR: unknown arch %%A. Use x86 / x64 / all.
            exit /b 1
        )
        if !errorlevel! neq 0 exit /b 1
    )
)

echo.
echo ============================================================
echo  All builds complete.
echo ============================================================
endlocal
exit /b 0

rem -----------------------------------------------------------------------
:one
    set _A=%~1
    set _P=%~2
    set _C=%~3
    set _DIR=build_%_A%

    echo.
    echo === [%_A%] [%_C%]  build_dir: %_DIR% ===

    "%CMAKE_EXE%" -B %_DIR% -A %_P% -Wno-dev
    if errorlevel 1 ( echo [ERROR] Configure failed & exit /b 1 )

    "%CMAKE_EXE%" --build %_DIR% --config %_C%
    if errorlevel 1 ( echo [ERROR] Build failed & exit /b 1 )

    echo [OK] %_DIR%\%_C%\dll_tracer.exe
    goto :eof
