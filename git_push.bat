@echo off
cd /d "C:\Users\Administrator\Desktop\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
del /f ".git\index.lock" 2>nul
"C:\Program Files\Git\cmd\git.exe" add .
"C:\Program Files\Git\cmd\git.exe" commit -m "feat: Global Customer Operations Transformation - 15-phase enterprise cybersecurity service org buildout"
"C:\Program Files\Git\cmd\git.exe" pull --rebase origin main
"C:\Program Files\Git\cmd\git.exe" push origin main
