# LaTeX Installation Guide

## Windows Installation Options

### Option 1: MiKTeX (Recommended)
1. Download MiKTeX from: https://miktex.org/download
2. Run the installer and follow the setup wizard
3. Choose "Install missing packages on-the-fly: Yes"
4. After installation, restart your command prompt

### Option 2: TeX Live
1. Download TeX Live from: https://www.tug.org/texlive/
2. Run the installer (this is a large download ~4GB)
3. Follow the installation wizard

### Option 3: Using Package Manager (if you have Chocolatey)
```cmd
choco install miktex
```

### Option 4: Using Scoop (if you have Scoop)
```cmd
scoop install latex
```

## Verification
After installation, verify by running:
```cmd
pdflatex --version
```

## Compilation Commands
Once LaTeX is installed, compile the report with:
```cmd
# Windows
compile_report.bat

# Or manually:
pdflatex report.tex
bibtex report
pdflatex report.tex
pdflatex report.tex
```

## Alternative: Online LaTeX Editors
If you prefer not to install LaTeX locally:
1. **Overleaf**: https://www.overleaf.com/ (free online LaTeX editor)
2. **ShareLaTeX**: Integrated into Overleaf
3. **CoCalc**: https://cocalc.com/

Simply upload the report.tex file to any of these platforms and compile online.