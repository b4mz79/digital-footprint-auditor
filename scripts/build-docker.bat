@echo off
setlocal EnableExtensions

cd /d "%~dp0.." || (
    echo [ERROR] Cannot enter the project directory.
    exit /b 1
)

set "IMAGE_TAG=%DOCKER_IMAGE%"
if "%IMAGE_TAG%"=="" set "IMAGE_TAG=privacy-auditor:dev"
set "RUN_TESTS=0"
set "NO_CACHE=0"

:parse
if "%~1"=="" goto parsed
if /i "%~1"=="--test" goto arg_test
if /i "%~1"=="--no-cache" goto arg_no_cache
if /i "%~1"=="--tag" goto arg_tag
if /i "%~1"=="--help" goto help
if "%~1"=="-h" goto help
echo [ERROR] Unknown argument: %~1
goto usage_error

:arg_test
set "RUN_TESTS=1"
shift
goto parse

:arg_no_cache
set "NO_CACHE=1"
shift
goto parse

:arg_tag
if "%~2"=="" (
    echo [ERROR] --tag requires an image name/tag.
    goto usage_error
)
set "IMAGE_TAG=%~2"
shift
shift
goto parse

:parsed
where docker >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker CLI not found. Install Docker Desktop first.
    exit /b 127
)

set "BUILD_FLAGS=--progress=plain"
if "%NO_CACHE%"=="1" set "BUILD_FLAGS=%BUILD_FLAGS% --no-cache"

if "%RUN_TESTS%"=="1" goto build_test

echo [INFO] Building Privacy Auditor runtime image: %IMAGE_TAG%
docker build %BUILD_FLAGS% --target runtime --tag "%IMAGE_TAG%" .
if errorlevel 1 exit /b %ERRORLEVEL%
echo [OK] Image built: %IMAGE_TAG%
echo [INFO] Run with: docker compose up --build
exit /b 0

:build_test
set "TEST_TAG=%IMAGE_TAG%-test"
echo [INFO] Building disposable test image: %TEST_TAG%
docker build %BUILD_FLAGS% --target test --tag "%TEST_TAG%" .
if errorlevel 1 exit /b %ERRORLEVEL%
echo [INFO] Running pytest in the test container...
docker run --rm "%TEST_TAG%"
exit /b %ERRORLEVEL%

:help
echo Usage: scripts\build-docker.bat [--test] [--no-cache] [--tag IMAGE:TAG]
echo.
echo   Default     Build the runtime image
echo   --test      Build the test image and run pytest inside it
echo   --no-cache  Build without Docker layer cache
echo   --tag       Set image name/tag (default: privacy-auditor:dev)
echo.
echo Examples:
echo   scripts\build-docker.bat
echo   scripts\build-docker.bat --test
echo   scripts\build-docker.bat --no-cache
echo   scripts\build-docker.bat --tag privacy-auditor:local
exit /b 0

:usage_error
echo.
echo Usage: scripts\build-docker.bat [--test] [--no-cache] [--tag IMAGE:TAG]
exit /b 2
