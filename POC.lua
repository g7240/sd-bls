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
   local sig = sign(A.sk + rev.sk, id)
   S_CLAIMS[id] = { sig, rev.pk:to_zcash() }
   A_REVOKES['HolderID/'..id] = rev.sk
end

I.warn(A_REVOKES)
-- holder discloses 3 credentials
disclose = { 'name', 'gender', 'above_18' }
SD_CLAIMS = { }
eph = keygen()
for k,v in pairs(S_CLAIMS) do
   local claim = strtok(k, '=')
   local revpk = ECP2.from_zcash(v[2])
   if array_contains(disclose, claim[1]) then
	  SD_CLAIMS[k] = { v[1] + sign(eph.sk, k), (revpk + eph.pk):to_zcash() }
   end
end

-- show encoded claims example
print(JSON.encode({claims = SD_CLAIMS,
				   verifier = 'IssuerID'}))

-- relying party verifies credentials
-- downloads PK of IssuerID from DID
for k,v in pairs(SD_CLAIMS) do
   local sig = v[1]
   local pk = ECP2.from_zcash(v[2])
   assert( verify(pk + A.pk, k, sig) )
end
