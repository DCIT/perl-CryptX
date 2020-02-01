@echo off
call :%*
goto :eof

:perl_setup
cinst -y wget
if "%perl_type%" == "cygwin" (
  start /wait c:\cygwin\setup-x86.exe -q -P perl -P make -P gcc -P gcc-g++ -P libcrypt-devel
  set "PATH=C:\cygwin\usr\local\bin;C:\cygwin\bin;%PATH%"
  wget -q --no-check-certificate https://cpanmin.us/ -O C:\cygwin\tmp\downloaded-cpanm
  perl /tmp/downloaded-cpanm -v --notest App::cpanminus
  dir C:\cygwin\usr\local\bin
) else if "%perl_type%" == "cygwin64" (
  rem -q --quiet-mode     Unattended setup mode
  rem -g --upgrade-also   also upgrade installed packages
  start /wait c:\cygwin\setup-x64.exe -q -P perl -P make -P gcc -P gcc-g++ -P libcrypt-devel
  set "PATH=C:\cygwin64\usr\local\bin;C:\cygwin64\bin;%PATH%"
  wget -q --no-check-certificate https://cpanmin.us/ -O C:\cygwin64\tmp\downloaded-cpanm
  perl /tmp/downloaded-cpanm -v --notest App::cpanminus
) else if "%perl_type%" == "strawberry" (
  wget -q http://strawberryperl.com/download/%perl_version%/strawberry-perl-%perl_version%-%perl_bits%bit-portable.zip -O downloaded-strawberry.zip
  7z x downloaded-strawberry.zip -oc:\spperl\
  set "PATH=c:\spperl\perl\site\bin;c:\spperl\perl\bin;c:\spperl\c\bin;%PATH%"
  wget -q --no-check-certificate https://cpanmin.us/ -O downloaded-cpanm
  perl downloaded-cpanm --notest App::cpanminus
) else if "%perl_type%" == "strawberry_old" (
  wget -q http://strawberryperl.com/download/%perl_version%/strawberry-perl-%perl_version%-portable.zip -O downloaded-strawberry.zip
  7z x downloaded-strawberry.zip -oc:\spperl\
  set "PATH=c:\spperl\perl\site\bin;c:\spperl\perl\bin;c:\spperl\c\bin;%PATH%"
  wget -q --no-check-certificate https://cpanmin.us/ -O downloaded-cpanm
  perl downloaded-cpanm --notest App::cpanminus
) else (
  echo.Unknown perl type "%perl_type%"! 1>&2
  exit /b 1
)

for /f "usebackq delims=" %%d in (`perl -MConfig -e"print $Config{make}"`) do set make=%%d

if "%make%" == "gmake" (
  set make=gmake -j4
)

:eof
