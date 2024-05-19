
STATS := issueproveverify.txt verifyrevocations.txt

all: issueproveverify.eps verifyrevocations.eps hamming.eps

# issueproveverify: ${STATS}
# 	 sed 's/OUT/$@.txt/; s/TERM/pngcairo dashed ${TERMOPTS}/' \
# 	 gnuplot.txt | gnuplot  > $@.png
# 	 sed 's/OUT/$@.txt/; s/TERM/eps/' \
# 	 gnuplot.txt | gnuplot  > $@.eps

# verifyrevocations: ${STATS}
# 	 sed 's/OUT/$@.txt/; s/TERM/pngcairo dashed ${TERMOPTS}/' \
# 	 $@.gnuplot | gnuplot  > $@.png
# 	 sed 's/OUT/$@.txt/; s/TERM/eps/' \
# 	 $@.gnuplot | gnuplot  > $@.eps

%.png: %.txt
	sed 's/TERM/pngcairo dashed rounded size 1024,768/' \
		$(basename $@).gnuplot | gnuplot  > $(basename $@).png

%.eps: %.txt
	sed 's/TERM/eps/' \
		$(basename $@).gnuplot | gnuplot  > $(basename $@).eps

%.txt: %.gnuplot
	zenroom -l common.lua ${basename $@}.lua | tee $@

clean:
	rm -f *.txt *.eps *.png
