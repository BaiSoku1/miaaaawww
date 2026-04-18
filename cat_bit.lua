-- cat_bit.lua: Portable bit-manipulation library (ed table + helpers).
local ed = {}
local function ee(d_)
    d_ = (d_ or 0) % 4294967296
    if d_ >= 2147483648 then
        d_ = d_ - 4294967296
    end
    return math.floor(d_)
end
ed.tobit = ee
ed.tohex = function(d_, U)
    return string.format("%0" .. (U or 8) .. "x", (d_ or 0) % 0x100000000)
end
-- EmulaciÃ³n bÃ¡sica de bitwise para Lua 5.1
local function bit_band(a, b)
    local r = 0
    local m = 1
    for i = 0, 31 do
        if a % 2 == 1 and b % 2 == 1 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_bor(a, b)
    local r = 0
    local m = 1
    for i = 0, 31 do
        if a % 2 == 1 or b % 2 == 1 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_bxor(a, b)
    local r = 0
    local m = 1
    for i = 0, 31 do
        if a % 2 ~= b % 2 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_lshift(a, b) return math.floor(a * (2 ^ b)) % 4294967296 end
local function bit_rshift(a, b) return math.floor(a / (2 ^ b)) end

_G.bit = {band = bit_band, bor = bit_bor, bxor = bit_bxor, lshift = bit_lshift, rshift = bit_rshift}
_G.bit32 = _G.bit
ed.band = bit_band
ed.bor = bit_bor
ed.bxor = bit_bxor
ed.lshift = bit_lshift
ed.rshift = bit_rshift
ed.bnot = function(a) return bit_bxor(bit_band(a % 0x100000000, 0xFFFFFFFF), 0xFFFFFFFF) end
ed.arshift = function(d_, U)
    local b5 = ee(d_ or 0)
    if b5 < 0 then
        return ee(bit_rshift(b5, U or 0)) + ee(bit_lshift(-1, 32 - (U or 0)))
    else
        return ee(bit_rshift(b5, U or 0))
    end
end
ed.rol = function(d_, U)
    d_ = d_ or 0
    U = (U or 0) % 32
    return ee(bit_bor(bit_lshift(d_, U), bit_rshift(d_, 32 - U)))
end
ed.ror = function(d_, U)
    d_ = d_ or 0
    U = (U or 0) % 32
    return ee(bit_bor(bit_rshift(d_, U), bit_lshift(d_, 32 - U)))
end
ed.bswap = function(d_)
    d_ = d_ or 0
    local bo = bit_band(bit_rshift(d_, 24), 0xFF)
    local aa = bit_band(bit_rshift(d_, 8), 0xFF00)
    local b0 = bit_band(bit_lshift(d_, 8), 0xFF0000)
    local b1 = bit_band(bit_lshift(d_, 24), 0xFF000000)
    return ee(bit_bor(bit_bor(bo, aa), bit_bor(b0, b1)))
end
ed.countlz = function(U)
    U = ed.tobit(U)
    if U == 0 then
        return 32
    end
    local a2 = 0
    if bit_band(U, 0xFFFF0000) == 0 then
        a2 = a2 + 16
        U = bit_lshift(U, 16)
    end
    if bit_band(U, 0xFF000000) == 0 then
        a2 = a2 + 8
        U = bit_lshift(U, 8)
    end
    if bit_band(U, 0xF0000000) == 0 then
        a2 = a2 + 4
        U = bit_lshift(U, 4)
    end
    if bit_band(U, 0xC0000000) == 0 then
        a2 = a2 + 2
        U = bit_lshift(U, 2)
    end
    if bit_band(U, 0x80000000) == 0 then
        a2 = a2 + 1
    end
    return a2
end
ed.countrz = function(U)
    U = ed.tobit(U)
    if U == 0 then
        return 32
    end
    local a2 = 0
    while bit_band(U, 1) == 0 do
        U = bit_rshift(U, 1)
        a2 = a2 + 1
    end
    return a2
end
ed.lrotate = ed.rol
ed.rrotate = ed.ror
ed.extract = function(U, eg, eh)
    eh = eh or 1
    return bit_band(bit_rshift(U, eg), bit_lshift(1, eh) - 1)
end
ed.replace = function(U, b5, eg, eh)
    eh = eh or 1
    local ei = bit_lshift(1, eh) - 1
    local mask = bit_lshift(ei, eg)
    return bit_bor(bit_band(U, 4294967295 - mask), bit_band(bit_lshift(b5, eg), mask))
end
ed.btest = function(bo, aa)
    return bit_band(bo, aa) ~= 0
end

return {
    ed        = ed,
    bit_band  = bit_band,
    bit_bor   = bit_bor,
    bit_bxor  = bit_bxor,
    bit_lshift = bit_lshift,
    bit_rshift = bit_rshift,
}
