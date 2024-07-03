PVSS = require_once'crypto_pvss'
TOTAL = 20
STEP = 1

GEN = PVSS.set_generators()
local PARTICIPANTS_PK = { }
local PARTICIPANTS_SK = { }

for i=1,TOTAL,STEP do
  local sk = PVSS.keygen()
  local pk = PVSS.sk2pk(GEN, sk)
  table.insert(PARTICIPANTS_SK,sk)
  table.insert(PARTICIPANTS_PK,pk)
end

SECRET = BIG.random()
-- SHA256 = HASH.new('sha256')
USABLE_SECRET = sha256(GEN.G*SECRET)

-- takes a list of PKS
-- t is the quorum
-- n is the number of participants
local total = #PARTICIPANTS_PK
local quorum = (total / 2 ) + 1

SHARES = PVSS.create_shares(GEN, SECRET, PARTICIPANTS_PK, quorum, total, false)

-- I.schema(SHARES)

assert( PVSS.verify_shares(GEN, quorum, total, SHARES) )

print(JSON.encode(SHARES))

-- RECONSTRUCTION

local dec
DEC = { }
for i=1, quorum do
  table.insert(DEC, PVSS.decrypt_share
  (GEN, PARTICIPANTS_SK[i], PARTICIPANTS_PK[i], SHARES))
end
VAL, IDX = PVSS.verify_decrypted_shares(GEN, DEC)

assert(
  sha256(PVSS.pooling_shares(VAL, IDX, quorum))
  ==
  USABLE_SECRET
)
