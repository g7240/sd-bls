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
H = ECP.hashtopoint
function keygen()
-- δ = r.O
-- γ = δ.G2
   local sk = INT.random()
   return { sk = sk,
			pk = G2 * sk }
end
function sign(sk, msg)
-- σ = δ * ( H(m)*G1 )
   return H(msg) * sk
end

function verify(pk, msg, sig)
-- e(γ,H(m)) == e(G2,σ)
   return(
	  PAIR.ate(pk, H(msg))
	  == PAIR.ate(G2, sig)
   )
end


--- s = A.sk + R.sk *G2 R.pk
--- p = s + E.sk
--- v ( A.pk + R.pk + E.pk - G.sk, m, p - G.sk)
D = keygen()
E = keygen()
F = keygen()
G = keygen()
local m = O.random(16)
local d = sign(D.sk, m)
local e = sign(E.sk, m)
local f = sign(F.sk, m)
local g = sign(G.sk, m)
s = d + e + f + g
p = D.pk + E.pk + F.pk + G.pk
assert( I.spy(verify(p, m, s)))

-- Issuer's keyring
A = keygen()

-- Holder sends claims to issuer and proves them
CLAIMS = { name = "Pasqualino",
		   surname = "Frafuso",
		   nickname = "Settebellezze",
		   born_in = "Napoli",
		   gender = "male",
		   above_18 = 'true',
		   nationality = "italian"
}

-- Issuer signs claims
S_CLAIMS = { }
A_REVOKES = { }
for k,v in pairs(CLAIMS) do
   local rev = keygen()
   local id = k..'='..v
   local sig = sign(A.sk, id) + sign(rev.sk, id)
   S_CLAIMS[id] = { sig, rev.pk }
   A_REVOKES['HolderID/'..id] = rev.sk
end

I.warn({ Revocations = A_REVOKES })
--         SignedClaims = S_CLAIMS })
-- holder discloses 3 credentials
disclose = { 'name', 'gender', 'above_18' }
SD_CLAIMS = { }
sha256 = HASH.new'sha256'
eph = keygen()
for m,v in pairs(S_CLAIMS) do
  local sig = v[1] -- naked issuer's sig
  local revpk = v[2]
  local claim = strtok(m, '=')
  if array_contains(disclose, claim[1]) then
	  table.insert(SD_CLAIMS, {
                   id = m,
                   s = sig + sign(eph.sk, m),
                   p = (revpk + eph.pk):to_zcash()
    })
  end
end

-- show encoded claims example
print(JSON.encode({
          claims = SD_CLAIMS,
          verifier = 'IssuerID'
}))

function revocation_contains(revocations, claim)
  local rs
  local res   = false -- store here result for constant time operations
  for _,rev in pairs(revocations) do
    local rsk = rev
    local tri = (PAIR.ate(A.pk, H(claim)) ^ rsk):octet()
    if H(tri) == rev[2] then
      res = true
    end
  end
  return res
end

local revocations = { A_REVOKES['HolderID/born_in=Napoli'],
--                      A_REVOKES['HolderID/gender=male'],
                      A_REVOKES['HolderID/nationality=italian'] }

-- relying party verifies credentials
-- downloads PK of IssuerID from DID
for _,claim in pairs(SD_CLAIMS) do
   local sig = claim.s
   local pk = ECP2.from_zcash(claim.p)
   assert(not revocation_contains(revocations, claim.id), "Revoked: "..claim.id)
   assert( verify(pk + A.pk, claim.id, sig) )
end
