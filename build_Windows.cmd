@echo off
setlocal enabledelayedexpansion

echo [*] Setting build environment for Windows...

rem Absolute path to the project root
set "ROOT=%CD%"

rem Default Cargo home (where registry sources live)
set "CARGO_HOME=%USERPROFILE%\.cargo"

rem Hardened build flags and path remapping
set "RUSTFLAGS=-C debuginfo=0 -C strip=symbols -C link-arg=/DEBUG:NONE -C link-arg=/CETCOMPAT -C link-arg=/NXCOMPAT -C link-arg=/DYNAMICBASE -C link-arg=/HIGHENTROPYVA --remap-path-prefix=%ROOT%=. --remap-path-prefix=%CARGO_HOME%=./cargo_home"

echo [*] RUSTFLAGS set to:
echo     %RUSTFLAGS%
echo.

echo [*] Cleaning build artifacts...
cargo clean
if errorlevel 1 goto :error

echo.
echo [*] Running cargo test...
cargo test
if errorlevel 1 goto :error

echo.
echo [*] Building release binary...
cargo build --release
if errorlevel 1 goto :error

echo.
echo [*] Build completed.

rem Optionally, uncomment this section to copy the binary next to the script
rem (assumes the binary name is 'rcrypt.exe'):

rem echo [*] Copying release binary to current directory...
rem copy /Y "target\release\rcrypt.exe" ".\rcrypt.exe"
rem if errorlevel 1 goto :error
rem echo [*] Copied rcrypt.exe to current directory.

goto :eof

:error
echo.
echo [!] An error occurred during build or tests.
exit /b 1
pause
