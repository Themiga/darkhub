local WORKER_URL = "https://darkhub-api.themiga.workers.dev"
local HMAC_SECRET = "DarkHubSecretKey"
local PLACE_ID = tostring(game.PlaceId)

local _req = (syn and syn.request) or (http and http.request) or http_request or (fluxus and fluxus.request) or request
if not _req then
    return warn("Executor not supported (HTTP req missing).")
end

-- =====================================
-- CRYPTO UTILS
-- =====================================
local function _sha256(msg)
    local function rr(v, n) return bit32.bor(bit32.rshift(v,n), bit32.lshift(v,32-n)) end
    local K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    }
    local H = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
    msg = msg .. "\128"
    local len = #msg
    while #msg % 64 ~= 56 do msg = msg .. "\0" end
    local bitLen = (len - 1) * 8
    for i = 7, 0, -1 do msg = msg .. string.char(math.floor(bitLen / 2^(i*8)) % 256) end
    for ci = 1, #msg / 64 do
        local chunk = msg:sub((ci-1)*64+1, ci*64)
        local w = {}
        for j = 1, 16 do
            local o = (j-1)*4
            w[j] = bit32.bor(bit32.lshift(chunk:byte(o+1),24),bit32.lshift(chunk:byte(o+2),16),bit32.lshift(chunk:byte(o+3),8),chunk:byte(o+4))
        end
        for j = 17, 64 do
            local s0 = bit32.bxor(rr(w[j-15],7), rr(w[j-15],18), bit32.rshift(w[j-15],3))
            local s1 = bit32.bxor(rr(w[j-2],17), rr(w[j-2],19), bit32.rshift(w[j-2],10))
            w[j] = (w[j-16]+s0+w[j-7]+s1) % 0x100000000
        end
        local a,b,c,d,e,f,g,h = table.unpack(H)
        for j = 1, 64 do
            local S1  = bit32.bxor(rr(e,6),rr(e,11),rr(e,25))
            local ch  = bit32.bxor(bit32.band(e,f),bit32.band(bit32.bnot(e),g))
            local t1  = (h+S1+ch+K[j]+w[j]) % 0x100000000
            local S0  = bit32.bxor(rr(a,2),rr(a,13),rr(a,22))
            local maj = bit32.bxor(bit32.band(a,b),bit32.band(a,c),bit32.band(b,c))
            local t2  = (S0+maj) % 0x100000000
            h=g;g=f;f=e;e=(d+t1)%0x100000000;d=c;c=b;b=a;a=(t1+t2)%0x100000000
        end
        H[1]=(H[1]+a)%0x100000000;H[2]=(H[2]+b)%0x100000000;H[3]=(H[3]+c)%0x100000000;H[4]=(H[4]+d)%0x100000000
        H[5]=(H[5]+e)%0x100000000;H[6]=(H[6]+f)%0x100000000;H[7]=(H[7]+g)%0x100000000;H[8]=(H[8]+h)%0x100000000
    end
    local r = ""
    for i = 1, 8 do r = r .. string.format("%08x", H[i]) end
    return r
end

local function _sha256bytes(msg)
    local hex = _sha256(msg)
    local bytes = ""
    for i = 1, #hex, 2 do bytes = bytes .. string.char(tonumber(hex:sub(i,i+1), 16)) end
    return bytes
end

local function _hmac256(key, message)
    local blockSize = 64
    if #key > blockSize then key = _sha256bytes(key) end
    key = key .. string.rep("\0", blockSize - #key)
    local ikey, okey = "", ""
    for i = 1, blockSize do
        local kb = key:byte(i)
        ikey = ikey .. string.char(bit32.bxor(kb, 0x36))
        okey = okey .. string.char(bit32.bxor(kb, 0x5c))
    end
    return _sha256(okey .. _sha256bytes(ikey .. message))
end

local function _randomHex(len)
    local chars = "0123456789abcdef"
    local out = {}
    for i = 1, len do
        local r = math.random(1, #chars)
        out[i] = chars:sub(r, r)
    end
    return table.concat(out)
end

-- =====================================
-- TEST FRAMEWORK
-- =====================================
print("\n==================================================")
print("🛡️ INICIANDO AUDITORIA DE SEGURANCA DARKHUB 🛡️")
print("==================================================\n")

local function runTest(name, endpoint, body, ua)
    print("\n▶ TESTE: " .. name)
    local res = _req({
        Url = WORKER_URL .. endpoint,
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json",
            ["User-Agent"] = ua or "DarkHub/1.0 RobloxGameClient"
        },
        Body = game:GetService("HttpService"):JSONEncode(body)
    })
    
    local isSuccess = res.StatusCode == 200
    local isBlocked = res.StatusCode == 403 or res.StatusCode == 404
    
    print("  Status Code : " .. tostring(res.StatusCode))
    print("  Response    : " .. tostring(res.Body))
    
    if isBlocked then
        print("  [✅ DEFESA ATIVADA]: Servidor bloqueou o ataque com sucesso.")
    elseif isSuccess then
        print("  [❌ ALERTA]: A requisicao passou pelo sistema.")
    else
        print("  [❓ INFO]: Erro desconhecido ou falha na requisicao.")
    end
end

-- 1. Teste de User-Agent Incorreto (Acesso fora do Roblox)
runTest(
    "Spoofing de User-Agent (fingir ser Navegador Chrome)", 
    "/api/loader/check", 
    { placeId = PLACE_ID, nonce = "123", signature = "123" }, 
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/100.0"
)

-- 2. Falsificacao de Assinatura
runTest(
    "Falsificacao de Assinatura (Hacker injetando dados)", 
    "/api/loader/check", 
    { placeId = PLACE_ID, nonce = "abcdef1234567890", signature = "assinatura_completamente_falsa" }
)

-- 3. Máquina do Tempo / Timestamp Expirado
local oldWindow = tostring(math.floor(os.time() / 30) - 10) -- 5 minutes ago
local oldNonce = _randomHex(16)
local oldSig = _hmac256(HMAC_SECRET, oldNonce .. ":" .. PLACE_ID .. ":" .. oldWindow)
runTest(
    "Assinatura Valida porem Vencida (Desincronia de Tempo)", 
    "/api/loader/check", 
    { placeId = PLACE_ID, nonce = oldNonce, signature = oldSig }
)

-- 4. Replay Attack (Interceptacao e Re-uso)
print("\n▶ Preparando Teste de Interceptacao (Replay Attack)...")
local validNonce = _randomHex(16)
local validWindow = tostring(math.floor(os.time() / 30))
local validSig = _hmac256(HMAC_SECRET, validNonce .. ":" .. PLACE_ID .. ":" .. validWindow)

print("  -> Enviando Requisicao Original (valida)...")
local res1 = _req({
    Url = WORKER_URL .. "/api/loader",
    Method = "POST",
    Headers = {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "DarkHub/1.0 RobloxGameClient"
    },
    Body = game:GetService("HttpService"):JSONEncode({
        placeId = PLACE_ID, nonce = validNonce, signature = validSig, jobHash = "test"
    })
})
print("  Status 1: " .. tostring(res1.StatusCode))

runTest(
    "Replay Attack (Tentando usar a mesma assinatura validada novamente)", 
    "/api/loader", 
    { placeId = PLACE_ID, nonce = validNonce, signature = validSig, jobHash = "test" }
)

print("\n==================================================")
print("🛡️ AUDITORIA CONCLUIDA 🛡️")
print("Se todas as defesas ativaram com o bloqueio do servidor, sua API esta blindada!")
print("==================================================\n")
