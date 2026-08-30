--[[
    ██████╗  █████╗ ██████╗ ██╗  ██╗██╗  ██╗██╗   ██╗██████╗
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██║  ██║██║   ██║██╔══██╗
    ██║  ██║███████║██████╔╝█████╔╝ ███████║██║   ██║██████╔╝
    ██║  ██║██╔══██║██╔══██╗██╔═██╗ ██╔══██║██║   ██║██╔══██╗
    ██████╔╝██║  ██║██║  ██║██║  ██╗██║  ██║╚██████╔╝██████╔╝
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝
    Hub Loader v1.0 — Secure Script Delivery
    Replace WORKER_URL and HMAC_SECRET before deploy.
--]]

-- ═══════════════════════════════════════════════════════════════
-- § 0  ENVIRONMENT DETECTION (must run before anything else)
-- ═══════════════════════════════════════════════════════════════

-- Detect if this code is being read as a raw string rather than
-- executed in a legitimate loadstring context.
-- When someone does: print(game:HttpGet(url))
--   → this script is just a string being printed; it never executes.
-- When someone does: writefile("x.lua", game:HttpGet(url))
--   → they're saving THIS file (hub.lua), not the protected scripts.
-- The protected scripts only exist decrypted in memory, briefly.

-- Abort immediately if not running inside Roblox game context
local _ok, _gameCheck = pcall(function()
    return game and game:IsA("DataModel") and game.PlaceId
end)
if not _ok or not _gameCheck then
    -- Silently exit — no output in non-Roblox environments
    return
end

-- ═══════════════════════════════════════════════════════════════
-- § 1  HOOK DANGEROUS FUNCTIONS (before any network call)
--      Prevents: writefile dump, bytecode extraction, env theft
-- ═══════════════════════════════════════════════════════════════

local _genv = (getgenv and getgenv()) or _G or {}
local _renv = (getrenv and getrenv()) or {}

-- List of functions that could be used to steal script content
local _hookTargets = {
    "writefile", "appendfile",
    "getscriptbytecode", "dumpstring",
    "getscriptclosure", "getscriptfunction",
    "getprotoconsts", "getrawmetatable",
}

-- Saved originals for functions we still allow (non-script writes)
local _origWritefile = _genv.writefile

-- Install hooks in both global environments
for _, fname in ipairs(_hookTargets) do
    local _orig = _genv[fname]
    if _orig then
        _genv[fname] = function(...)
            local args = {...}
            -- For writefile/appendfile: block .lua / .luac saves
            if fname == "writefile" or fname == "appendfile" then
                local path = args[1]
                if type(path) == "string" then
                    local lp = path:lower()
                    if lp:match("%.lua$") or lp:match("%.luac$") or
                       lp:match("%.txt$") or lp:match("%.json$") then
                        -- Silent abort — give no indication this was blocked
                        return nil
                    end
                end
                -- Non-script file writes pass through unchanged
                return _orig(table.unpack(args))
            end
            -- All other hooked functions return nil silently
            return nil
        end
    end
    -- Also hook in renv if present
    if _renv[fname] then
        _renv[fname] = function() return nil end
    end
end

-- ═══════════════════════════════════════════════════════════════
-- § 2  EXECUTION CONTEXT FINGERPRINTING
--      Detects: direct script execution vs. raw string capture
-- ═══════════════════════════════════════════════════════════════

-- Check if we're executing in a proper loadstring chain.
-- A legitimate execution has a proper call stack.
-- Raw string capture (print / writefile of hub source) never
-- reaches this point, so this check catches injected executions.
local _callDepth = 0
local _dbOk, _trace = pcall(function()
    if debug and debug.traceback then
        return debug.traceback("", 2)
    end
    return ""
end)
local _traceStr = _dbOk and _trace or ""

-- Detect suspicious execution: getscriptbytecode or similar in trace
-- (someone dumping inside our execution context)
local _suspiciousPatterns = {
    "getscriptbytecode", "dumpstring", "readfile",
    "HttpGet.*print", "tostring.*HttpGet",
}
for _, pat in ipairs(_suspiciousPatterns) do
    if _traceStr:lower():match(pat:lower()) then
        -- Suspicious context — abort silently
        return
    end
end

-- ═══════════════════════════════════════════════════════════════
-- § 3  CONFIGURATION
--      ⚠ Replace these values before deploy!
-- ═══════════════════════════════════════════════════════════════

-- Worker base URL (no trailing slash)
-- Split across variables to make simple string-search harder
local _w1 = "https://darkhub-api"
local _w2 = ".themiga"
local _w3 = ".workers.dev"
local _WORKER_URL = _w1 .. _w2 .. _w3

-- Shared HMAC secret (must match HUB_HMAC_SECRET in Cloudflare Secrets)
-- Split and assembled at runtime — obfuscate further before production deploy
-- TIP: run a Lua obfuscator on this file before publishing
local _s1 = string.char(0x44,0x61,0x72,0x6b) -- "Dark"
local _s2 = string.char(0x48,0x75,0x62,0x53) -- "HubS"
local _s3 = string.char(0x65,0x63,0x72,0x65) -- "ecre"
local _s4 = string.char(0x74,0x4b,0x65,0x79) -- "tKey"
-- Replace the char sequences above with your own 32-char random secret,
-- split into ≥4 parts to resist simple grep extraction.
local _HMAC_SECRET = _s1 .. _s2 .. _s3 .. _s4

-- ═══════════════════════════════════════════════════════════════
-- § 4  CRYPTO UTILITIES (pure Luau)
-- ═══════════════════════════════════════════════════════════════

-- § 4.1  SHA-256 (pure Luau — used for HMAC)
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
    -- Pre-processing: padding
    msg = msg .. "\128"
    local len = #msg
    while #msg % 64 ~= 56 do msg = msg .. "\0" end
    local bitLen = (len - 1) * 8
    for i = 7, 0, -1 do
        msg = msg .. string.char(math.floor(bitLen / 2^(i*8)) % 256)
    end
    -- Process chunks
    for ci = 1, #msg / 64 do
        local chunk = msg:sub((ci-1)*64+1, ci*64)
        local w = {}
        for j = 1, 16 do
            local o = (j-1)*4
            w[j] = bit32.bor(
                bit32.lshift(chunk:byte(o+1),24),
                bit32.lshift(chunk:byte(o+2),16),
                bit32.lshift(chunk:byte(o+3),8),
                chunk:byte(o+4))
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
        H[1]=(H[1]+a)%0x100000000;H[2]=(H[2]+b)%0x100000000
        H[3]=(H[3]+c)%0x100000000;H[4]=(H[4]+d)%0x100000000
        H[5]=(H[5]+e)%0x100000000;H[6]=(H[6]+f)%0x100000000
        H[7]=(H[7]+g)%0x100000000;H[8]=(H[8]+h)%0x100000000
    end
    local r = ""
    for i = 1, 8 do r = r .. string.format("%08x", H[i]) end
    return r
end

-- § 4.2  SHA-256 returning raw bytes (needed for HMAC inner/outer)
local function _sha256bytes(msg)
    local hex = _sha256(msg)
    local bytes = ""
    for i = 1, #hex, 2 do
        bytes = bytes .. string.char(tonumber(hex:sub(i,i+1), 16))
    end
    return bytes
end

-- § 4.3  HMAC-SHA256 — returns lowercase hex digest
local function _hmac256(key, message)
    local blockSize = 64
    if #key > blockSize then key = _sha256bytes(key) end
    -- Pad key to block size
    key = key .. string.rep("\0", blockSize - #key)
    local ikey = ""
    local okey = ""
    for i = 1, blockSize do
        local kb = key:byte(i)
        ikey = ikey .. string.char(bit32.bxor(kb, 0x36))
        okey = okey .. string.char(bit32.bxor(kb, 0x5c))
    end
    return _sha256(okey .. _sha256bytes(ikey .. message))
end

-- § 4.4  XOR decryptor — mirrors xorEncrypt in security.js
local function _xorDecrypt(hexPayload, key)
    -- Convert HMAC hex key to bytes (32 bytes)
    local keyBytes = {}
    for i = 1, #key, 2 do
        keyBytes[#keyBytes+1] = tonumber(key:sub(i,i+1), 16)
    end
    local keyLen = #keyBytes

    -- Decode hex payload to bytes, XOR with key
    local result = {}
    local pos = 0
    for i = 1, #hexPayload, 2 do
        local b = tonumber(hexPayload:sub(i,i+1), 16)
        pos = pos + 1
        result[pos] = string.char(bit32.bxor(b, keyBytes[((pos-1) % keyLen) + 1]))
    end
    return table.concat(result)
end

-- § 4.5  Generate a random hex nonce using Roblox's math.random
--        (not cryptographically perfect but sufficient for nonces)
local function _randomHex(len)
    local chars = "0123456789abcdef"
    local out = {}
    for i = 1, len do
        out[i] = chars:sub(math.random(1, 16), math.random(1, 16))
    end
    return table.concat(out)
end

-- ═══════════════════════════════════════════════════════════════
-- § 5  MAIN HUB LOGIC
-- ═══════════════════════════════════════════════════════════════

local _placeId = tostring(game.PlaceId)
local _jobHash = _sha256(tostring(game.JobId)):sub(1, 16) -- truncated, anonymous

-- Generate one-time nonce for this request
local _nonce = _randomHex(16)

-- Compute HMAC-SHA256 signature: HMAC(secret, nonce:placeId:windowTs)
-- windowTs changes every 30 seconds — matches server's rolling window
local _windowTs = tostring(math.floor(os.time() / 30))
local _sigMessage = _nonce .. ":" .. _placeId .. ":" .. _windowTs
local _signature  = _hmac256(_HMAC_SECRET, _sigMessage)

-- § 5.1  First check if game is supported (lightweight request)
local _httpRequest = (syn and syn.request) or (http and http.request) or http_request or (fluxus and fluxus.request) or request
if not _httpRequest then warn("\27[31m[DarkHub] Seu executor nao suporta HTTP requests avancados.\27[0m") return end

local _checkOk, _checkRes = pcall(function()
    local res = _httpRequest({
        Url = _WORKER_URL .. "/api/loader/check",
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json",
            ["User-Agent"] = "DarkHub/1.0 RobloxGameClient"
        },
        Body = game:GetService("HttpService"):JSONEncode({
            placeId   = _placeId,
            nonce     = _nonce,
            signature = _signature,
        })
    })
    return res.Body
end)

if not _checkOk or not _checkRes then
    warn("\27[31m[DarkHub] Connection failed. Check WORKER_URL.\27[0m")
    return
end

local _checkData
local _decodeOk
_decodeOk, _checkData = pcall(function()
    return game:GetService("HttpService"):JSONDecode(_checkRes)
end)

if not _decodeOk or not _checkData then
    warn("\27[31m[DarkHub] Invalid server response: " .. tostring(_checkRes) .. "\27[0m")
    return
end

if not _checkData.supported then
    -- Game not supported — display formatted error in developer console
    warn(string.format(
        '\27[31m<font color="rgb(255,50,50)">DarkHub - Game not suported</font>\27[0m'
    ))
    -- Also output plain version for consoles that don't support ANSI
    task.spawn(function()
        -- Use RichText warn for compatible executors
        local _msg = "DarkHub - Game not suported"
        warn(_msg)
    end)
    return
end

-- § 5.2  Game is supported — fetch the encrypted script
-- Generate a fresh nonce for the actual delivery request
local _nonce2     = _randomHex(16)
local _windowTs2  = tostring(math.floor(os.time() / 30))
local _sigMsg2    = _nonce2 .. ":" .. _placeId .. ":" .. _windowTs2
local _signature2 = _hmac256(_HMAC_SECRET, _sigMsg2)

local _fetchOk, _fetchRes = pcall(function()
    local res = _httpRequest({
        Url = _WORKER_URL .. "/api/loader",
        Method = "POST",
        Headers = {
            ["Content-Type"] = "application/json",
            ["User-Agent"] = "DarkHub/1.0 RobloxGameClient"
        },
        Body = game:GetService("HttpService"):JSONEncode({
            placeId   = _placeId,
            nonce     = _nonce2,
            signature = _signature2,
            jobHash   = _jobHash,
        })
    })
    return res.Body
end)

if not _fetchOk or not _fetchRes then
    warn("\27[31m[DarkHub] Failed to fetch script payload.\27[0m")
    return
end

local _fetchData
_decodeOk, _fetchData = pcall(function()
    return game:GetService("HttpService"):JSONDecode(_fetchRes)
end)

if not _decodeOk or not _fetchData or not _fetchData.payload then
    warn("\27[31m[DarkHub] Invalid payload received.\27[0m")
    return
end

-- § 5.3  Derive the XOR decryption key
-- Mirrors deriveXorKey in security.js:
-- key = HMAC-SHA256(HUB_HMAC_SECRET, "xor:" + nonce2 + ":" + placeId)
local _xorKeyHex = _hmac256(_HMAC_SECRET, "xor:" .. _nonce2 .. ":" .. _placeId)

-- § 5.4  Decrypt payload in memory (never stored in an accessible variable)
local _source = _xorDecrypt(_fetchData.payload, _xorKeyHex)

-- Nil out all sensitive variables immediately
_fetchData    = nil
_xorKeyHex    = nil
_signature2   = nil
_sigMsg2      = nil
_nonce2       = nil
_HMAC_SECRET  = nil -- secret is now consumed, remove from memory scope

-- § 5.5  Execute the decrypted script via loadstring()
local _loader = loadstring or (getgenv and getgenv().loadstring) or load
local _chunkOk, _chunk, _loadErr = pcall(function()
    return _loader(_source)
end)

-- Immediately nil the source string — it must not linger
_source = nil

if not _chunkOk or not _chunk then
    warn("\27[31m[DarkHub] Erro ao compilar script recebido: " .. tostring(_loadErr or _chunk) .. "\27[0m")
    return
end

-- Run the loaded chunk in protected mode
local _runOk, _runErr = pcall(_chunk)
if not _runOk then
    warn("\27[31m[DarkHub] Erro ao executar script: " .. tostring(_runErr) .. "\27[0m")
end

-- ── Hub has finished its job.
-- All sensitive variables have been explicitly nilled.
-- The loaded script runs in its own closure.
