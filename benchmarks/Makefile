
STATS := issueproveverify.txt
TERMOPTS := rounded size 1024,768

all: issueproveverify # verifyrevocations

issueproveverify: ${STATS}
	 sed 's/OUT/$@.txt/; s/TERM/pngcairo dashed ${TERMOPTS}/' \
	 gnuplot.txt | gnuplot  > $@.png
	 sed 's/OUT/$@.txt/; s/TERM/eps ${TERMOPTS}/' \
	 gnuplot.txt | gnuplot  > $@.eps

verifyrevocations: ${STATS}
	 sed 's/OUT/$@.txt/' gnuplot.txt | gnuplot  > $@.png

issueproveverify.txt:
	zenroom -l common.lua bench.lua | tee $@
