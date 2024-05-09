# Privacy Preserving Selective Disclosure and Issuer Revocation of Verifiable Credentials


It is of critical importance to design digital identity systems that
ensure the privacy of citizens as well protect them from state
corruption as the identity issuer. Unfortunately, what Europe and USA
state organizations are currently developing does not offer such basic
protections. As a solution we introduce a method for untraceable
selective disclosure and privacy preserving revocation of digital
credentials, utilizing the unique homomorphic characteristics of
second order Elliptic Curves and Boneh-Lynn-Shacham (BLS) signatures
operated on them. Our approach ensures that users can selectively
reveal only the necessary attributes, while protecting their privacy
across multiple presentations and against colluding verifiers. Since
we also want to protect users from issuer corruption, we apply a
threshold for credential issuance and revocation to mandate a
collective agreement among multiple issuers. Finally, our method of
revocation does not give out any information on the identity of
holders of revoked credentials.

## Add references

Add any reference used in text inside the [references.bib](https://github.com/dyne/sd-bls/blob/master/references.bib) file in BibTeX format.

Add references inside the text using the `\cite{..}` tag, i.e. `\cite{bls381-12}` for the article named `bls381-12` inside the `references.bib` file.


## Build from source

Do an `apt-get install` of the following packages:
```
 texlive-extra-utils texlive-latex-recommended texlive-font-utils \
 texlive-fonts-extra texlive-latex-extra texlive-fonts-recommended \
 texlive-science
```

Then do `make` to build the latest `sd-bls.pdf` from this repo.
