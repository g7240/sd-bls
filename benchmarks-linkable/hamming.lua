-- hamming.lua
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

SAMPLES = 1000

CLAIMS, REVOC, T = test_many_issuance(1)
PROOFS, T = test_many_proofs(1, CLAIMS)
local prev = PROOFS[1]
local rlen = #(prev.r):octet()
print "Sign \t Pub \t Rev \t Rand"
for i=1,SAMPLES,1 do
  PROOFS, T = test_many_proofs(1, CLAIMS)
  local proof = PROOFS[1]
  -- test hamming of s, p, r
  local sh = O.hamming(proof.s:octet(), prev.s:octet())
  local ph = O.hamming(proof.p:octet(), prev.p:octet())
  local rh = O.hamming(proof.r:octet(), prev.r:octet())
  local zh = O.hamming(O.random(rlen), O.random(rlen))
  print(sh.." \t "..ph.." \t "..rh.." \t "..zh)
  prev = proof
end
