
STATS := issueproveverify.txt verifyrevocations.txt
TERMOPTS := rounded size 1024,768

all: issueproveverify verifyrevocations

issueproveverify: ${STATS}
	 sed 's/OUT/$@.txt/; s/TERM/pngcairo dashed ${TERMOPTS}/' \
	 gnuplot.txt | gnuplot  > $@.png
	 sed 's/OUT/$@.txt/; s/TERM/eps/' \
	 gnuplot.txt | gnuplot  > $@.eps

verifyrevocations: ${STATS}
	 sed 's/OUT/$@.txt/; s/TERM/pngcairo dashed ${TERMOPTS}/' \
	 $@.gnuplot | gnuplot  > $@.png
	 sed 's/OUT/$@.txt/; s/TERM/eps/' \
	 $@.gnuplot | gnuplot  > $@.eps

issueproveverify.txt:
	zenroom -l common.lua bench.lua | tee $@

verifyrevocations.txt:
	zenroom -l common.lua revoc.lua | tee $@

clean:
	rm -f ${STATS}
