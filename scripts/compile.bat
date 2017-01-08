mkdir ..\build
copy "C:\Program Files (x86)\SASM\include\io.inc" ..\io.inc
"C:\Program Files (x86)\SASM\NASM\nasm.exe" -g -f win32 ..\%1.asm -o ..\build\%1.obj -i ../
"C:/Program Files (x86)/SASM/MinGW/bin/gcc.exe" ..\build\%1.obj -g -o ..\build\%1.exe -m32

