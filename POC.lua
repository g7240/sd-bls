-- Copyright (C) 2024 Dyne.org foundation designed, written and
-- maintained by Denis Roio <jaromil@dyne.org>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU Affero General Public License as
-- published by the Free Software Foundation, either version 3 of the
-- License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
-- Affero General Public License for more details.
--
-- You should have received a copy of the GNU Affero General Public
-- License along with this program.  If not, see
-- <https://www.gnu.org/licenses/>.

CONF.output.encoding = { fun = get_encoding_function'url64',
                         name = 'url64' }
-- Simple BLS signature formula
-- δ = r.O
-- γ = δ.G2
-- σ = δ * ( H(m)*G1 )
-- assume: ε(δ*G2, H(m)) == ε(G2, δ*H(m))
-- check:  ε(γ, H(m))    == ε(G2, σ)


-- SD-BLS adds revocation key signature formula
-- ρ = β * ( H(m)*G1 )
-- σ = σ + ρ
-- assume:
-- v(σ - ρ, δ*G2)
-- where:
-- G1, G2 = generator points for ECP1, ECP2
G1 = ECP.generator()
G2 = ECP2.generator()
-- H =  hash to point function to ECP1
HG1 = ECP.hashtopoint
Miller = PAIR.ate

function keygen()
-- δ = r.O
-- γ = δ.G2
   local sk = INT.random()
   return { sk = sk,
			pk = G2 * sk }
end
function sign(sk, msg)
-- σ = δ * ( H(m)*G1 )
   return HG1(msg) * sk
end

function verify(pk, msg, sig)
-- e(γ,H(m)) == e(G2,σ)
   return(
	  Miller(pk, HG1(msg))
	  ==
    Miller(G2, sig)
   )
end

-- Issuer's keyring hardcoded 0x0 seed
A = {sk = BIG.new(sha256(OCTET.zero(32)))}
A.pk = G2*A.sk

-- Holder sends claims to issuer and proves them
CLAIMS = {
  name = "Pasqualino",
  surname = "Frafuso",
  nickname = "Settebellezze",
  born_in = "Napoli",
  gender = "male",
  above_18 = 'true',
  nationality = "italian"
}

-- Issuer signs claims
SIGNED_CLAIMS = { }
REVOCATIONS = { }
for k,v in pairs(CLAIMS) do
   local rev = BIG.random()
   local id = k..'='..v
   local sig = sign(A.sk, id) + sign(rev, id)
   SIGNED_CLAIMS[id] = { sig, G1 * rev, G2 * rev }
   REVOCATIONS['HolderID/'..id] = rev
end

--I.warn({ Revocations = A_REVOKES })
--         SignedClaims = S_CLAIMS })
-- holder discloses 3 credentials
disclose = { 'name', 'gender', 'above_18' }
CREDENTIAL_PROOF = { }
sha256 = HASH.new('sha256')
local tri
for m,v in pairs(SIGNED_CLAIMS) do
  local sig = v[1] -- naked issuer's sig
  local revG1 = v[2]
  local revG2 = v[3]
  local claim = strtok(m, '=')
  local er = BIG.random()
  local tri = BIG.new(sha256:process(
                  (Miller(A.pk, revG1) ^ er):octet()
  ))
  -- assert(tri == BIG.new(sha256:process(
  --                        (PAIR.ate(A.pk, G1*er)^rev):octet()
  -- )))
  if array_contains(disclose, claim[1]) then
	  table.insert(CREDENTIAL_PROOF, {
                   id = m,
                   s = sig + sign(tri, m),
                   p = (revG2 + G2*tri):to_zcash(),
                   r = G1*er
    })
  end
end

function revocation_contains(revocations, claim)
  local res   = false -- store here result for constant time operations
  local rev = revocations[claim.id]
  if rev then
    local tri =
      BIG.new(
        sha256:process(
          (Miller(A.pk,claim.r)^rev)
          :octet()
      ))

    if -- addendum of claim.p is equal to revG2
      ECP2.from_zcash(claim.p) - (G2*tri) == G2*rev
    and -- verify unblinded issuer signature
      verify(A.pk, claim.id,
             claim.s
             - sign(tri, claim.id)
             - sign(rev, claim.id))
    then
      res = true
    end
  end
  return res
end

local torevoke = {
  'HolderID/born_in=Napoli',
  'HolderID/gender=male',
  'HolderID/nationality=italian'}
local revocations = {}
for _,v in pairs(torevoke) do
  local k = strtok(v,'/')[2]
  revocations[k] = REVOCATIONS[v]
end


-- show encoded claims example
print(JSON.encode({
          credential_proof = CREDENTIAL_PROOF,
          verifier = 'IssuerID',
          revocations = revocations
}))

-- relying party verifies credentials
-- downloads PK of IssuerID from DID
for _,proof in pairs(CREDENTIAL_PROOF) do
   local sig = proof.s
   local pk = ECP2.from_zcash(proof.p)
   assert(not revocation_contains(revocations, proof), "Revoked: "..proof.id)
   assert( verify(pk + A.pk, proof.id, sig) )
end
