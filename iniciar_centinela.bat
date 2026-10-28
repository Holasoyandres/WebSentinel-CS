@echo off
title WebSentinel-CS :: Cyber Security Sentinel
color 0b
echo ========================================================
echo    WebSentinel-CS: Security & Anomaly Detection Sentinel
echo    Desarrollado por Holasoyandres
echo ========================================================
echo.
echo [1/2] Iniciando servidor de monitoreo en el puerto 4000...
start "" "http://localhost:4000"
node server.js
pause
