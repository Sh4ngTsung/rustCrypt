@echo off
setlocal enabledelayedexpansion

echo [rcrypt-build] Setting hardened build environment for Windows...

rem Absolute path to the project root.
set "ROOT=%CD%"
set "CARGO_HOME=%USERPROFILE%\.cargo"

rem MSVC hardening flags:
rem   /CETCOMPAT       Hardware-enforced shadow stacks (Control-flow Enforcement).
rem   /NXCOMPAT        Data Execution Prevention.
rem   /DYNAMICBASE     Address Space Layout Randomization.
rem   /HIGHENTROPYVA   64-bit ASLR with high-entropy.
rem   /GUARD:CF        Control Flow Guard (where supported).
rem   /DEBUG:NONE      Strip PDB / debug data from the binary.
set "RUSTFLAGS=-C debuginfo=0 -C strip=symbols -C overflow-checks=on -C link-arg=/DEBUG:NONE -C link-arg=/CETCOMPAT -C link-arg=/NXCOMPAT -C link-arg=/DYNAMICBASE -C link-arg=/HIGHENTROPYVA -C link-arg=/GUARD:CF --remap-path-prefix=%ROOT%=. --remap-path-prefix=%CARGO_HOME%=./cargo_home"

echo [rcrypt-build] RUSTFLAGS:
echo     %RUSTFLAGS%
echo.

echo [rcrypt-build] Cleaning build artefacts...
cargo clean
if errorlevel 1 goto :error

echo.
echo [rcrypt-build] Running cargo test --release ...
cargo test --release --all-targets
if errorlevel 1 goto :error

echo.
echo [rcrypt-build] Building hardened release binary ...
cargo build --release
if errorlevel 1 goto :error

echo.
echo [rcrypt-build] Build completed. Output: target\release\rcrypt.exe
goto :eof

:error
echo.
echo [rcrypt-build] An error occurred during build or tests.
exit /b 1
