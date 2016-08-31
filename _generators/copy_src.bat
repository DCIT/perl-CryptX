@echo off
echo STARTED...
xcopy /Y y:\_repos\libtommath\*.c d:\git\cryptx\src\ltm
xcopy /Y y:\_repos\libtommath\*.h d:\git\cryptx\src\ltm
xcopy /Y /E y:\_repos\libtomcrypt\src\* d:\git\cryptx\src\ltc
perl fix_src.pl
echo DONE!
pause