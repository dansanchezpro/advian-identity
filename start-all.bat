@echo off
echo Starting IdentityServer solution...
echo.

echo Starting IdentityServer.Api (port 5000)...
start cmd /k "cd /d C:\SC\Code\advian-identity\src\IdentityServer.Api && dotnet run"

timeout /t 3 /nobreak >nul

echo Starting IdentityServer.Web (port 7000)...
start cmd /k "cd /d C:\SC\Code\advian-identity\src\IdentityServer.Web && dotnet run"

timeout /t 2 /nobreak >nul

echo Starting SampleApp1 (port 7001)...
start cmd /k "cd /d C:\SC\Code\advian-identity\src\SampleApp1 && dotnet run"

timeout /t 2 /nobreak >nul

echo Starting SampleApp2 (port 7002)...
start cmd /k "cd /d C:\SC\Code\advian-identity\src\SampleApp2 && dotnet run"

timeout /t 2 /nobreak >nul

echo Starting SampleApp3 (port 7003)...
start cmd /k "cd /d C:\SC\Code\advian-identity\src\SampleApp3 && dotnet run"

timeout /t 2 /nobreak >nul

echo Starting SampleBack1 API (port 6001)...
start cmd /k "cd /d C:\SC\Code\advian-identity\src\SampleBack1 && dotnet run"

echo.
echo All applications are starting...
echo API: https://localhost:5000
echo Web: https://localhost:7000  
echo SampleApp1: https://localhost:7001
echo SampleApp2: https://localhost:7002
echo SampleApp3: https://localhost:7003
echo SampleBack1: https://localhost:6001
pause