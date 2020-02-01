@echo off
call :%*
goto :eof

:perl_setup
echo perl_type=%perl_type%
echo perl_version=%perl_version%
echo perl_bits=%perl_bits%
dir c:\cygwin\
dir c:\

if "%perl_type%" == "cygwin" (
  start /wait c:\cygwin\setup-x86.exe -q -P perl -P make -P gcc -P gcc-g++ -P libcrypt-devel
  set "PATH=C:\cygwin\usr\local\bin;C:\cygwin\bin;%PATH%"
) else if "%perl_type%" == "cygwin64" (
  start /wait c:\cygwin\setup-x64.exe -q -P perl -P make -P gcc -P gcc-g++ -P libcrypt-devel
  set "PATH=C:\cygwin64\usr\local\bin;C:\cygwin64\bin;%PATH%"
) else if "%perl_type%" == "strawberry" (
  wget -q http://strawberryperl.com/download/%perl_version%/strawberry-perl-%perl_version%-%perl_bits%bit-portable.zip -O downloaded-strawberry.zip
  7z x downloaded-strawberry.zip -oc:\spperl\
  set "PATH=c:\spperl\perl\bin;c:\spperl\perl\site\bin;c:\spperl\c\bin;%PATH%"
  wget -q --no-check-certificate https://cpanmin.us/ -O downloaded-cpanm
  perl downloaded-cpanm --notest App::cpanminus
) else (
  echo.Unknown perl type "%perl_type%"! 1>&2
  exit /b 1
)

for /f "usebackq delims=" %%d in (`perl -MConfig -e"print $Config{make}"`) do set make=%%d

if "%make%" == "gmake" (
  make=gmake -j4
)

:eof
