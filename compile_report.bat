@echo off
REM Batch script to compile LaTeX report on Windows

echo Compiling Advanced LLMs Cybersecurity Report...
echo.

REM Check if pdflatex is available
where pdflatex >nul 2>nul
if %errorlevel% neq 0 (
    echo Error: pdflatex not found in PATH
    echo Please install MiKTeX or TeX Live and ensure pdflatex is in your PATH
    pause
    exit /b 1
)

REM First compilation
echo Running first pdflatex compilation...
pdflatex report.tex
if %errorlevel% neq 0 (
    echo Error during first compilation
    pause
    exit /b 1
)

REM BibTeX compilation
echo Running bibtex...
bibtex report
if %errorlevel% neq 0 (
    echo Warning: BibTeX compilation failed, continuing...
)

REM Second compilation
echo Running second pdflatex compilation...
pdflatex report.tex
if %errorlevel% neq 0 (
    echo Error during second compilation
    pause
    exit /b 1
)

REM Third compilation (for cross-references)
echo Running final pdflatex compilation...
pdflatex report.tex
if %errorlevel% neq 0 (
    echo Error during final compilation
    pause
    exit /b 1
)

echo.
echo Compilation successful! Generated report.pdf
echo.

REM Open PDF if available
if exist report.pdf (
    echo Opening report.pdf...
    start report.pdf
) else (
    echo Error: report.pdf was not generated
)

pause