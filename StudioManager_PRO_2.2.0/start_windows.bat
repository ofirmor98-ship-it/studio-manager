@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ================================================
echo   Studio Manager Online - הפעלה מקומית
echo ================================================
set /p STUDIO_ADMIN_KEY=הקלד מפתח מנהל ארוך וסודי (לא לשתף עם לקוחות):
if "%STUDIO_ADMIN_KEY%"=="" (
  echo חובה להגדיר מפתח מנהל.
  pause
  exit /b 1
)
set PORT=3000
node server.js
pause
