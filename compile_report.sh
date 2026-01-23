#!/bin/bash

# Shell script to compile LaTeX report on Linux/Mac

echo "Compiling Advanced LLMs Cybersecurity Report..."
echo

# Check if pdflatex is available
if ! command -v pdflatex &> /dev/null; then
    echo "Error: pdflatex not found in PATH"
    echo "Please install TeX Live or MacTeX and ensure pdflatex is in your PATH"
    exit 1
fi

# First compilation
echo "Running first pdflatex compilation..."
pdflatex report.tex
if [ $? -ne 0 ]; then
    echo "Error during first compilation"
    exit 1
fi

# BibTeX compilation
echo "Running bibtex..."
bibtex report
if [ $? -ne 0 ]; then
    echo "Warning: BibTeX compilation failed, continuing..."
fi

# Second compilation
echo "Running second pdflatex compilation..."
pdflatex report.tex
if [ $? -ne 0 ]; then
    echo "Error during second compilation"
    exit 1
fi

# Third compilation (for cross-references)
echo "Running final pdflatex compilation..."
pdflatex report.tex
if [ $? -ne 0 ]; then
    echo "Error during final compilation"
    exit 1
fi

echo
echo "Compilation successful! Generated report.pdf"
echo

# Open PDF if available
if [ -f "report.pdf" ]; then
    echo "Opening report.pdf..."
    if command -v xdg-open &> /dev/null; then
        xdg-open report.pdf
    elif command -v open &> /dev/null; then
        open report.pdf
    else
        echo "Please open report.pdf manually"
    fi
else
    echo "Error: report.pdf was not generated"
fi