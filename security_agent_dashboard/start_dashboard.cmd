@echo off
cd /d %~dp0
set DB_USER=qwet
set DB_PASSWORD=123456
python start_server.py
