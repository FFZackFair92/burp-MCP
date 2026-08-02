@echo off
REM Build dell'estensione senza Gradle: serve solo un JDK 17+ nel PATH.
REM Scarica montoya-api da Maven Central, compila e crea il JAR.
setlocal
cd /d "%~dp0"

set MONTOYA_VER=2026.4
set MONTOYA_JAR=lib\montoya-api-%MONTOYA_VER%.jar
set MONTOYA_URL=https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/%MONTOYA_VER%/montoya-api-%MONTOYA_VER%.jar

where javac >nul 2>&1
if errorlevel 1 (
  echo [ERRORE] javac non trovato nel PATH. Installa un JDK 17+ ^(es. Temurin^) e riprova.
  exit /b 1
)

if not exist lib mkdir lib
if not exist "%MONTOYA_JAR%" (
  echo Scarico Montoya API %MONTOYA_VER% da Maven Central...
  powershell -NoProfile -Command "try { Invoke-WebRequest -Uri '%MONTOYA_URL%' -OutFile '%MONTOYA_JAR%' } catch { Write-Host $_.Exception.Message; exit 1 }"
  if errorlevel 1 ( echo [ERRORE] Download di Montoya fallito. & exit /b 1 )
)

if exist build rmdir /s /q build
mkdir build\classes

echo Compilo...
dir /s /b src\main\java\*.java > build\sources.txt
javac -cp "%MONTOYA_JAR%" -d build\classes @build\sources.txt
if errorlevel 1 ( echo [ERRORE] Compilazione fallita. & exit /b 1 )

if not exist "build\libs" mkdir "build\libs"
echo Creo il JAR...
jar cf "build\libs\burp-mcp-bridge-0.1.0.jar" -C "build\classes" .
if errorlevel 1 ( echo [ERRORE] Creazione del JAR fallita. & exit /b 1 )

echo.
echo OK  -^>  extension\build\libs\burp-mcp-bridge-0.1.0.jar
echo Caricalo in Burp: Extensions ^> Add ^> Java ^> seleziona il .jar
endlocal
