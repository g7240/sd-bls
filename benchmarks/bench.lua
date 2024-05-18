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

A = keygen()
sha256 = HASH.new('sha256')
TOTAL = 100
STEP = 5

function test_many_issuance(num)
  local start = os.clock()
  claims = { }
  revocs = { }
  for i=1,num do
    local claim = OCTET.random(32)
    local rev = BIG.modrand(ECP.order())
    local sig = sign(A.sk, claim) + sign(rev, claim)
    table.insert(claims, {
                   c = claim,
                   s = sig,
                   r1 = G1 * rev,
                   r2 = G2 * rev
    })
    table.insert(revocs, { claim, rev })
  end
  return claims, revocs, os.clock() - start
end

function test_many_proofs(num, creds)
  local start = os.clock()
  proofs = { }
  local c = 0
  for k,v in ipairs(creds) do
    local sig = v.s -- naked issuer's sig
    local revG1 = v.r1
    local revG2 = v.r2
    local er = BIG.random()
    local tri = BIG.new(sha256:process(
                          (Miller(A.pk, revG1) ^ er):octet()
    ))
    table.insert(proofs, {
                   id = v.c,
                   s = sig + sign(tri, v.c),
                   p = (revG2 + G2*tri):to_zcash(),
                   r = G1*er
    })
    c = c + 1
    if c == num then break end
  end
  return proofs, os.clock() - start
end

function test_many_verifs(num, proofs)
  local start = os.clock()
  local c = 0

  for k,v in ipairs(proofs) do
    local sig = v.s
    local pk = ECP2.from_zcash(v.p)
    assert( verify(pk + A.pk, v.id, sig) )
    c = c + 1
    if c == num then break end
  end
  return os.clock() - start
end

TOTAL = TOTAL + STEP -- off by one fix
print "issuance "
local ISSUANCE_T = { }
for i=10,TOTAL,STEP do
  write(i.." ")
  CLAIMS, REVOCS, T = test_many_issuance(i)
  table.insert(ISSUANCE_T, T)
end
collectgarbage'collect'
collectgarbage'collect'

print''
print "proof "
local PROOF_T = { }
for i=10,TOTAL,STEP do
  write(i.." ")
  PROOFS, T = test_many_proofs(i, CLAIMS)
  table.insert(PROOF_T, T)
end
collectgarbage'collect'
collectgarbage'collect'

print''
print "verification "
local VERIF_T = { }
for i=10,TOTAL,STEP do
  write(i.." ")
  T = test_many_verifs(i, PROOFS)
  table.insert(VERIF_T, T)
end
collectgarbage'collect'
collectgarbage'collect'

print''
print("CLAIMS \t ISSUE \t PROVE \t VERIFY")
for i=1,(TOTAL/STEP),1 do
  write(i*STEP)
  write(' \t ')
  write(ISSUANCE_T[i])
  write(' \t ')
  write(PROOF_T[i])
  write(' \t ')
  write(VERIF_T[i])
  write('\n')
end

--   print(i..' \t\t '..ISSUANCE_T[i]..' \t\t '..PROOF_T[i])
-- end
