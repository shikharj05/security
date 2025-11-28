@echo off
REM Copyright OpenSearch Contributors
REM SPDX-License-Identifier: Apache-2.0
REM
REM The OpenSearch Contributors require contributions made to
REM this file be licensed under the Apache-2.0 license or a
REM compatible open source license.

REM Configuration Migration Tool
REM Migrates old authentication/authorization backend configurations
REM to the new plugin-based configuration format.

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set BASE_DIR=%SCRIPT_DIR%..

REM Check if running from the correct directory
if not exist "%BASE_DIR%\build.gradle" (
    echo Error: This script must be run from the OpenSearch Security plugin directory
    exit /b 1
)

REM Parse command line arguments
set OLD_CONFIG=
set NEW_CONFIG=
set VERBOSE=false
set DRY_RUN=false

:parse_args
if "%~1"=="" goto check_args
if /i "%~1"=="-h" goto show_usage
if /i "%~1"=="--help" goto show_usage
if /i "%~1"=="-v" (
    set VERBOSE=true
    shift
    goto parse_args
)
if /i "%~1"=="--verbose" (
    set VERBOSE=true
    shift
    goto parse_args
)
if /i "%~1"=="-d" (
    set DRY_RUN=true
    shift
    goto parse_args
)
if /i "%~1"=="--dry-run" (
    set DRY_RUN=true
    shift
    goto parse_args
)
if "!OLD_CONFIG!"=="" (
    set OLD_CONFIG=%~1
    shift
    goto parse_args
)
if "!NEW_CONFIG!"=="" (
    set NEW_CONFIG=%~1
    shift
    goto parse_args
)
echo Error: Too many arguments
goto show_usage

:check_args
if "!OLD_CONFIG!"=="" (
    echo Error: old-config-path is required
    goto show_usage
)
if "!NEW_CONFIG!"=="" (
    echo Error: new-config-path is required
    goto show_usage
)

REM Check if old config exists
if not exist "!OLD_CONFIG!" (
    echo Error: Old configuration file not found: !OLD_CONFIG!
    exit /b 1
)

REM Check if new config already exists
if exist "!NEW_CONFIG!" (
    if "!DRY_RUN!"=="false" (
        set /p REPLY="Warning: New configuration file already exists. Overwrite? (y/N) "
        if /i not "!REPLY!"=="y" (
            echo Migration cancelled
            exit /b 0
        )
    )
)

REM Find the JAR file
set JAR_FILE=
for %%f in ("%BASE_DIR%\build\libs\opensearch-security-*.jar") do (
    set JAR_FILE=%%f
    goto found_jar
)

:found_jar
if "!JAR_FILE!"=="" (
    echo Error: OpenSearch Security JAR file not found
    echo Please build the project first: gradlew.bat build
    exit /b 1
)

REM Build classpath
set CLASSPATH=!JAR_FILE!
for %%f in ("%BASE_DIR%\build\libs\*.jar") do (
    set CLASSPATH=!CLASSPATH!;%%f
)

REM Add dependencies
if exist "%BASE_DIR%\build\dependencies" (
    for %%f in ("%BASE_DIR%\build\dependencies\*.jar") do (
        set CLASSPATH=!CLASSPATH!;%%f
    )
)

REM Run the migration tool
if "!VERBOSE!"=="true" (
    echo Running configuration migration...
    echo Old config: !OLD_CONFIG!
    echo New config: !NEW_CONFIG!
    echo Classpath: !CLASSPATH!
    echo.
)

if "!DRY_RUN!"=="true" (
    echo DRY RUN MODE - No files will be modified
    echo.
)

REM Execute the migration
java -cp "!CLASSPATH!" org.opensearch.security.tools.ConfigMigrationTool "!OLD_CONFIG!" "!NEW_CONFIG!"

if %ERRORLEVEL% equ 0 (
    echo.
    echo Migration completed successfully!
    echo.
    echo IMPORTANT: Please review the new configuration before using it in production.
    echo The new configuration has been written to: !NEW_CONFIG!
    echo.
    echo Next steps:
    echo 1. Review the migrated configuration
    echo 2. Test the configuration in a non-production environment
    echo 3. Update your OpenSearch Security configuration
    echo 4. Restart OpenSearch
) else (
    echo.
    echo Migration failed. Please check the error messages above.
    exit /b 1
)

goto :eof

:show_usage
echo Usage: %~nx0 [OPTIONS] ^<old-config-path^> ^<new-config-path^>
echo.
echo Migrates old authentication/authorization backend configurations
echo to the new plugin-based configuration format.
echo.
echo Arguments:
echo   old-config-path    Path to the old config.yml file
echo   new-config-path    Path where the new configuration should be written
echo.
echo Options:
echo   -h, --help         Display this help message
echo   -v, --verbose      Enable verbose output
echo   -d, --dry-run      Show what would be migrated without writing output
echo.
echo Examples:
echo   # Migrate configuration
echo   %~nx0 C:\opensearch\config.yml C:\opensearch\config-new.yml
echo.
echo   # Dry run to preview migration
echo   %~nx0 --dry-run C:\opensearch\config.yml C:\temp\config-preview.yml
echo.
exit /b 1
