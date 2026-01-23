@echo off
REM Batch script to compile LaTeX report "1.tex" on Windows

echo Compiling Advanced LLMs Cybersecurity Report (1.tex)...
echo.

REM Check if pdflatex is available
set PDFLATEX="C:\Program Files\MiKTeX\miktex\bin\x64\pdflatex.exe"
set BIBTEX="C:\Program Files\MiKTeX\miktex\bin\x64\bibtex.exe"

if not exist %PDFLATEX% (
    echo Error: MiKTeX pdflatex not found at expected location
    echo Please check your MiKTeX installation
    pause
    exit /b 1
)

REM First compilation
echo Running first pdflatex compilation...
%PDFLATEX% 1.tex
if %errorlevel% neq 0 (
    echo Error during first compilation
    pause
    exit /b 1
)

REM BibTeX compilation
echo Running bibtex...
%BIBTEX% 1
if %errorlevel% neq 0 (
    echo Warning: BibTeX compilation failed, continuing...
)

REM Second compilation
echo Running second pdflatex compilation...
%PDFLATEX% 1.tex
if %errorlevel% neq 0 (
    echo Error during second compilation
    pause
    exit /b 1
)

REM Third compilation (for cross-references)
echo Running final pdflatex compilation...
%PDFLATEX% 1.tex
if %errorlevel% neq 0 (
    echo Error during final compilation
    pause
    exit /b 1
)

echo.
echo Compilation successful! Generated 1.pdf
echo.

REM Open PDF if available
if exist 1.pdf (
    echo Opening 1.pdf...
    start 1.pdf
) else (
    echo Error: 1.pdf was not generated
)

pause