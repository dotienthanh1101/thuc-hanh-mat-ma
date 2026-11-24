"""Mã hóa một khối DES bằng cấu trúc Feistel 16 vòng."""

from des_tables import E, FP, IP, P, PC1, PC2, SBOXES, SHIFTS

MASK28 = (1 << 28) - 1
MASK32 = (1 << 32) - 1


def permute(value, input_bits, table):
    result = 0
    for source_position in table:
        bit = (value >> (input_bits - source_position)) & 1
        result = (result << 1) | bit
    return result


def rotate28(value, count):
    return ((value << count) | (value >> (28 - count))) & MASK28


def expand_key(key, trace):
    selected = permute(key, 64, PC1)
    left, right = selected >> 28, selected & MASK28
    trace("ks.00.PC1", selected, 14)
    trace("ks.00.C", left, 7)
    trace("ks.00.D", right, 7)

    subkeys = []
    for number, shift in enumerate(SHIFTS, start=1):
        prefix = f"ks.{number:02}"
        left, right = rotate28(left, shift), rotate28(right, shift)
        trace(f"{prefix}.C", left, 7)
        trace(f"{prefix}.D", right, 7)
        subkey = permute((left << 28) | right, 56, PC2)
        trace(f"{prefix}.K", subkey, 12)
        subkeys.append(subkey)
    return subkeys


def feistel(right, subkey, prefix, trace):
    expanded = permute(right, 32, E)
    mixed = expanded ^ subkey
    trace(f"{prefix}.E", expanded, 12)
    trace(f"{prefix}.E_xor_K", mixed, 12)

    substituted = 0
    for index, box in enumerate(SBOXES):
        group = (mixed >> (42 - index * 6)) & 0x3F
        row = ((group >> 5) << 1) | (group & 1)
        column = (group >> 1) & 0x0F
        value = int(box[row][column], 16)
        trace(f"{prefix}.S{index + 1}.input", group, 2)
        trace(f"{prefix}.S{index + 1}.row", row, 1)
        trace(f"{prefix}.S{index + 1}.column", column, 1)
        trace(f"{prefix}.S{index + 1}.output", value, 1)
        substituted = (substituted << 4) | value

    trace(f"{prefix}.S", substituted, 8)
    result = permute(substituted, 32, P)
    trace(f"{prefix}.P", result, 8)
    return result


def encrypt(block, key, trace):
    if len(block) != 8 or len(key) != 8:
        raise ValueError("DES cần bản rõ và khóa, mỗi giá trị đúng 8 byte.")
    trace("plaintext", block)
    trace("key", key)
    subkeys = expand_key(int.from_bytes(key, "big"), trace)

    state = permute(int.from_bytes(block, "big"), 64, IP)
    left, right = state >> 32, state & MASK32
    trace("r.00.IP", state, 16)
    trace("r.00.L", left, 8)
    trace("r.00.R", right, 8)

    for number, subkey in enumerate(subkeys, start=1):
        prefix = f"r.{number:02}"
        trace(f"{prefix}.L_in", left, 8)
        trace(f"{prefix}.R_in", right, 8)
        trace(f"{prefix}.K", subkey, 12)
        transformed = feistel(right, subkey, prefix, trace)
        left, right = right, left ^ transformed
        trace(f"{prefix}.L", left, 8)
        trace(f"{prefix}.R", right, 8)

    swapped = (right << 32) | left
    trace("r.16.swap", swapped, 16)
    ciphertext = permute(swapped, 64, FP).to_bytes(8, "big")
    trace("ciphertext", ciphertext)
    return ciphertext
