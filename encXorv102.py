import base64
import os
import sys
import argparse


### Mode multi-line (default)
# $python encXorv102.py -o output.lua -k SecretKey input.lua 

### Mode single-line
# $python encXorv102.py -o output.lua -k SecretKey input.lua --single-line
# $python encXorv102.py -o output.lua -k SecretKey input.lua -s


def encrypt_lua_code(lua_code: str, key: str, single_line: bool = False) -> str:
    """
    Mengenkripsi kode Lua menjadi skrip self-decrypting
    """
    # Enkripsi XOR
    key_bytes = key.encode()
    encrypted_bytes = bytearray()
    for i, byte in enumerate(lua_code.encode()):
        encrypted_bytes.append(byte ^ key_bytes[i % len(key_bytes)])
    
    # Base64 encoding
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    
    # Format output base64
    if single_line:
        formatted_b64 = encrypted_b64
    else:
        formatted_b64 = '\n'.join([encrypted_b64[i:i+76] for i in range(0, len(encrypted_b64), 76)])
    
    # Generate skrip Lua dengan decryptor
    return f"""
-- Base64 decoder dengan cache
local function base64_decode(data)
    local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local cache = {{}}
    for i=0,63 do cache[b64:sub(i+1,i+1)] = i end
    
    data = data:gsub("[^%w+/=]", "")  -- Bersihkan karakter non-base64
    local result = {{}}
    local buffer, bits, idx = 0, 0, 1
    
    for i = 1, #data do
        local c = data:sub(i,i)
        if c == '=' then break end
        buffer = (buffer << 6) + cache[c]
        bits = bits + 6
        if bits >= 8 then
            bits = bits - 8
            result[idx] = string.char((buffer >> bits) & 0xFF)
            idx = idx + 1
            buffer = buffer & ((1 << bits) - 1)
        end
    end
    
    return table.concat(result)
end

-- XOR decryption
local function xor_decrypt(data, key)
    local kb = {{key:byte(1, -1)}}
    local kl = #kb
    local result = {{}}
    
    for i = 1, #data do
        local bytes = data:byte(i)
        result[i] = string.char(bytes ~ kb[(i-1) % kl + 1])
    end
    
    return table.concat(result)
end

-- Eksekusi kode dengan chunking
local function execute_code(code)
    local chunks = {{}}
    local pattern = "([^\\r\\n]*)\\r?\\n?"
    
    for line in code:gmatch(pattern) do
        if line ~= "" then
            table.insert(chunks, line)
            if #chunks >= 2000 then  -- Eksekusi per 1000 baris
                local chunk = table.concat(chunks, "\\n")
                load(chunk)()
                chunks = {{}}
            end
        end
    end
    
    if #chunks > 0 then
        load(table.concat(chunks, "\\n"))()
    end
end

-- Main process
local decoded = base64_decode([[{formatted_b64}]])
local decrypted = xor_decrypt(decoded, [[{key}]])
execute_code(decrypted)
"""

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Lua Code Encryptor')
    parser.add_argument('input', help='Input Lua file')
    parser.add_argument('-o', '--output', help='Output file', default='encrypted.lua')
    parser.add_argument('-k', '--key', help='Encryption key (required)', required=True)
    parser.add_argument('-s', '--single-line', action='store_true', 
                        help='Output encrypted data as single line without newlines')
    
    args = parser.parse_args()

    input_file = args.input
    output_file = args.output
    key = args.key
    single_line = args.single_line

    try:
        # Validasi kunci
        if len(key) < 8:
            print("Warning: Encryption key is too short (minimum 8 characters)")
        
        # Baca file input
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            print(f"Reading {os.path.basename(input_file)}...")
            lua_code = f.read()
            print(f"Read {len(lua_code)} characters")
            
        # Proses enkripsi
        print("Encrypting code...")
        encrypted = encrypt_lua_code(lua_code, key, single_line)
        
        # Tulis output
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(encrypted)
        
        # Laporan hasil
        print(f"Encrypted code written to {output_file}")
        print(f"Output size: {len(encrypted)} characters")
        print(f"Base64 format: {'Single line' if single_line else 'Multi-line'}")
        print(f"Encryption key: {key}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
