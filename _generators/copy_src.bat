@echo off
echo STARTED...
xcopy /Y y:\_repos\libtommath\*.c y:\_repos\_mygit\perl-cryptx\libtommath-src
xcopy /Y y:\_repos\libtommath\*.h y:\_repos\_mygit\perl-cryptx\libtommath-src
xcopy /Y /E y:\_repos\libtomcrypt\src\* y:\_repos\_mygit\perl-cryptx\libtomcrypt-src
perl fix_src.pl
echo DONE!
pause