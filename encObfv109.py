import re
import random
import string
import sys
import os
import argparse

# panjang huruf obfiuscate
obflength = 4


### Mode multi-line (default)
# $python encObfv109.py input.lua -o output.lua

### Mode single-line
# $python encObfv109.py input.lua -o output.lua --single-line
# $python encObfv109.py input.lua -o output.lua --s


# Keyword dan fungsi bawaan Lua
LUA_KEYWORDS = {
    'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 'function',
    'goto', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 'return', 'then',
    'true', 'until', 'while', 'x', 'y', 'px', 'py', 'name', 'GetWorld', 'GetTile', 'GetLocal',
    'userid', 'LogToConsole', 'SendVariantList', 'SendPacketRaw', 'SendPacket', 'item', '_',
    'id', 'amount', 'find', 'self', 'byte'
}
LUA_BUILTINS = {
    'assert', 'collectgarbage', 'dofile', 'error', 'getmetatable', 'ipairs', 
    'load', 'loadfile', 'next', 'pairs', 'pcall', 'print', 'rawequal', 
    'rawget', 'rawlen', 'rawset', 'require', 'select', 'setmetatable', 
    'tonumber', 'tostring', 'type', 'xpcall', '_G', '_VERSION'
}

def generate_random_identifier(existing_ids, length=obflength):
    """Generate unique random identifier"""
    chars = string.ascii_letters + string.digits
    while True:
        candidate = ''.join(random.choice(chars) for _ in range(length))
        if (
            candidate not in existing_ids and
            candidate not in LUA_KEYWORDS and
            candidate not in LUA_BUILTINS and
            not candidate[0].isdigit()
        ):
            return candidate

def find_declarations(code):
    """
    Temukan semua deklarasi yang perlu diobfuscate:
    - Fungsi global (baik bentuk 'function name()' maupun 'name = function()')
    - Variabel lokal (termasuk parameter fungsi dan loop variables)
    """
    declarations = set()

    # 1. Fungsi global: function name(...)
    global_func_matches = re.finditer(
        r'(?<!local\s)\bfunction\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
        code
    )
    for match in global_func_matches:
        declarations.add(match.group(1))

    # 2. Fungsi global: name = function(...)
    global_assign_matches = re.finditer(
        r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*function\s*\(',
        code
    )
    for match in global_assign_matches:
        declarations.add(match.group(1))

    # 3. Variabel lokal: local name
    local_matches = re.finditer(
        r'\blocal\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_]*)*)',
        code
    )
    for match in local_matches:
        vars_str = match.group(1)
        vars_list = [v.strip() for v in re.split(r'\s*,\s*', vars_str)]
        declarations.update(vars_list)

    # 4. Parameter fungsi
    param_matches = re.finditer(
        r'\bfunction\s*(?:[a-zA-Z_.:][a-zA-Z0-9_.:]*)?\s*\(([^)]*)\)',
        code
    )
    for match in param_matches:
        params_str = match.group(1)
        params_list = [p.strip() for p in re.split(r'\s*,\s*', params_str) if p.strip()]
        declarations.update(params_list)

    # 5. Variabel loop
    loop_matches = re.finditer(
        r'\bfor\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:[=,]|in\b)',
        code
    )
    for match in loop_matches:
        declarations.add(match.group(1))

    # 6. Fungsi lokal: local function name(...)
    local_func_matches = re.finditer(
        r'\blocal\s+function\s+([a-zA-Z_][a-zA-Z0-9_]*)',
        code
    )
    for match in local_func_matches:
        declarations.add(match.group(1))

    return declarations

def is_protected_access(identifier, code):
    """Cek jika identifier digunakan dalam akses properti/fungsi (seperti GetLocal().name)"""
    pattern = r'[a-zA-Z0-9_\]\)]\.\s*' + re.escape(identifier) + r'\b'
    if re.search(pattern, code):
        return True
    return False

def obfuscate_lua_code(code, single_line=False):
    """Obfuscate Lua code: rename functions dan local variables, keep non-function globals"""
    # Hapus komentar
    code = re.sub(r'--\[\[.*?\]\]', '', code, flags=re.DOTALL)
    code = re.sub(r'--[^\n]*', '', code)
    
    # Ekstrak semua string literal
    strings = []
    def string_replacer(match):
        strings.append(match.group(0))
        return f"__STRING_{len(strings)-1}__"
    
    code = re.sub(
        r'(\'[^\']*\'|\"[^\"]*\"|\[\[.*?\]\])', 
        string_replacer, 
        code, 
        flags=re.DOTALL
    )
    
    # Temukan deklarasi yang perlu diobfuscate
    declarations = find_declarations(code)
    
    # Buat pemetaan untuk deklarasi
    random.seed(0)
    mapping = {}
    existing_ids = set()
    protected_identifiers = set()
    
    # Identifikasi identifier yang harus dilindungi (akses properti/fungsi)
    for decl in declarations:
        if is_protected_access(decl, code):
            protected_identifiers.add(decl)
    
    for decl in declarations:
        if (
            decl not in LUA_KEYWORDS and
            decl not in LUA_BUILTINS and
            decl not in mapping and
            decl not in protected_identifiers
        ):
            mapping[decl] = generate_random_identifier(existing_ids)
            existing_ids.add(mapping[decl])
    
    # Ganti deklarasi dengan nama acak (urut dari terpanjang untuk menghindari konflik)
    sorted_decls = sorted(mapping.keys(), key=len, reverse=False)
    for old_name in sorted_decls:
        code = re.sub(r'\b' + re.escape(old_name) + r'\b', mapping[old_name], code)
    
    ############################################################
    # [BARU] Gabungkan baris dengan titik koma (mode single-line)
    if single_line:
        lines = code.split('\n')
        non_empty_lines = []
        for line in lines:
            stripped = line.strip()
            if stripped:
                non_empty_lines.append(stripped)
        # Gabungkan dengan ';'
        code = ';'.join(non_empty_lines)


    # Kembalikan string literal
    for i, string_val in enumerate(strings):
        code = code.replace(f"__STRING_{i}__", string_val)
    
    # Minify: Hapus spasi berlebihan
    if single_line:
        # Kompres seluruh kode menjadi satu baris
        code = re.sub(r'\s+', ' ', code)           # Ganti semua whitespace dengan spasi
        code = re.sub(r'\s*([=,{}()[\];])\s*', r'\1', code)  # Hapus spasi di sekitar simbol
        code = re.sub(r'([^<>])\s*([<>])\s*([^=])', r'\1\2\3', code)  # Operator khusus
        code = re.sub(r'([^<>])\s*([<>])\s*$', r'\1\2', code)  # Operator di akhir baris



        code = re.sub(r';+', '; ', code)  # Gabungkan titik koma berturut-turut jadi satu
        code = code.strip(';')            # Hapus titik koma di awal/akhir

        code = re.sub(r'\{\s*;\s*', '{', code)
        code = re.sub(r';\s*\}', '}', code)

        code = re.sub(r',\s*;\s*', ', ', code)


    else:
        # Pertahankan struktur baris
        lines = code.split('\n')
        minified_lines = []
        
        for line in lines:
            # Lewati baris kosong
            if not line.strip():
                minified_lines.append('')
                continue
            
            # Hapus spasi berlebihan
            line = re.sub(r'\s+', ' ', line)           # Ganti spasi ganda
            line = re.sub(r'\s*([=,{}()[\];])\s*', r'\1', line)  # Hapus spasi di sekitar simbol
            line = re.sub(r'([^<>])\s*([<>])\s*([^=])', r'\1\2\3', line)  # Operator khusus
            line = re.sub(r'([^<>])\s*([<>])\s*$', r'\1\2', line)  # Operator di akhir baris
            minified_lines.append(line.strip())
        
        code = '\n'.join(minified_lines)
    
    return code

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Lua Code Obfuscator')
    parser.add_argument('input', help='Input Lua file')
    parser.add_argument('-o', '--output', help='Output file', default='obfuscated.lua')
    parser.add_argument('-s', '--single-line', action='store_true', help='Output as a single line without newlines')
    args = parser.parse_args()

    input_file = args.input
    output_file = args.output
    single_line = args.single_line

    try:
        # Baca file input dengan penanganan encoding
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            print(f"Reading {os.path.basename(input_file)}...")
            lua_code = f.read()
            print(f"Read {len(lua_code)} characters")
            
        print("Obfuscating code...")
        obfuscated = obfuscate_lua_code(lua_code, single_line)
        
        # Tulis output
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(obfuscated)
            print(f"Obfuscated code written to {output_file}")
            print(f"Output size: {len(obfuscated)} characters")
            if single_line:
                print("Output format: Single line")
            else:
                print("Output format: Multi-line")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
