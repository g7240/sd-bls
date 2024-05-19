
arxiv: compose-arxiv
	pdflatex sd-bls
	bibtex   sd-bls
	pdflatex sd-bls
	pdflatex sd-bls

# epstopdf verifyrevocations.eps
# epstopdf issueproveverify.eps
# epstopdf hamming.eps

ieee: compose-ieee
	pdflatex sd-bls
	bibtex   sd-bls
	pdflatex sd-bls
	pdflatex sd-bls

compose-ieee:
	cat sd-bls.head-ieee.tex sd-bls.body.tex > sd-bls.tex

compose-arxiv:
	cat sd-bls.head-arxiv.tex sd-bls.body.tex > sd-bls.tex

clean:
	rm -f *blg *bbl *dvi *pdf *toc *out *aux *log *lof
	rm -f *converted-to*
