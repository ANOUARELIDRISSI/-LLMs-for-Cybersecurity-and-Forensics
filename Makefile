# Makefile for LaTeX document compilation

# Document name (without .tex extension)
DOC = report

# LaTeX compiler
LATEX = pdflatex

# BibTeX compiler
BIBTEX = bibtex

# Default target
all: $(DOC).pdf

# Compile PDF
$(DOC).pdf: $(DOC).tex
	$(LATEX) $(DOC).tex
	$(BIBTEX) $(DOC)
	$(LATEX) $(DOC).tex
	$(LATEX) $(DOC).tex

# Clean auxiliary files
clean:
	rm -f *.aux *.bbl *.blg *.log *.out *.toc *.lof *.lot *.fls *.fdb_latexmk *.synctex.gz

# Clean all generated files including PDF
cleanall: clean
	rm -f $(DOC).pdf

# Force rebuild
rebuild: cleanall all

# View PDF (Linux/Mac)
view: $(DOC).pdf
	@if command -v xdg-open > /dev/null; then \
		xdg-open $(DOC).pdf; \
	elif command -v open > /dev/null; then \
		open $(DOC).pdf; \
	else \
		echo "Please open $(DOC).pdf manually"; \
	fi

# Help
help:
	@echo "Available targets:"
	@echo "  all      - Compile the PDF document (default)"
	@echo "  clean    - Remove auxiliary files"
	@echo "  cleanall - Remove all generated files including PDF"
	@echo "  rebuild  - Clean and rebuild everything"
	@echo "  view     - Open the PDF document"
	@echo "  help     - Show this help message"

.PHONY: all clean cleanall rebuild view help