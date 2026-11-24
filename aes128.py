"""Mã hóa một khối AES-128. State dùng thứ tự byte theo cột."""

MIX_MATRIX = (
    (2, 3, 1, 1),
    (1, 2, 3, 1),
    (1, 1, 2, 3),
    (3, 1, 1, 2),
)


def xtime(value):
    """Nhân một byte với x trong GF(2^8), modulo đa thức 0x11B."""
    shifted = value << 1
    return shifted ^ 0x11B if shifted & 0x100 else shifted


def gf_multiply(left, right):
    result = 0
    while right:
        if right & 1:
            result ^= left
        left = xtime(left)
        right >>= 1
    return result


def rotate_byte(value, count):
    return ((value << count) | (value >> (8 - count))) & 0xFF


def sbox_entry(value):
    # Với byte khác 0, nghịch đảo là value^254. Byte 00 được ánh xạ về 00
    # trước phép affine. Tính lũy thừa bằng bình phương liên tiếp.
    inverse = 0
    if value:
        inverse = 1
        power = value
        for bit in range(8):
            if 254 & (1 << bit):
                inverse = gf_multiply(inverse, power)
            power = gf_multiply(power, power)
    return (
        inverse ^ rotate_byte(inverse, 1) ^ rotate_byte(inverse, 2)
        ^ rotate_byte(inverse, 3) ^ rotate_byte(inverse, 4) ^ 0x63
    )


SBOX = bytes(sbox_entry(value) for value in range(256))


def xor_bytes(left, right):
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def expand_key(key, trace):
    trace("ks.00.K", key)
    words = [key[i:i + 4] for i in range(0, 16, 4)]
    round_keys = [key]
    rcon = 1
    for number in range(1, 11):
        prefix = f"ks.{number:02}"
        previous = words[-1]
        rotated = previous[1:] + previous[:1]
        substituted = rotated.translate(SBOX)
        rcon_word = bytes([rcon, 0, 0, 0])
        transformed = xor_bytes(substituted, rcon_word)
        trace(f"{prefix}.RotWord", rotated)
        trace(f"{prefix}.SubWord", substituted)
        trace(f"{prefix}.Rcon", rcon_word)
        trace(f"{prefix}.g", transformed)

        for offset in range(4):
            index = number * 4 + offset
            word = xor_bytes(words[index - 4], transformed)
            words.append(word)
            transformed = word
            trace(f"{prefix}.w{index}", word)

        round_keys.append(b"".join(words[-4:]))
        trace(f"{prefix}.K", round_keys[-1])
        rcon = xtime(rcon)
    return round_keys


def shift_rows(state):
    # Byte ở hàng r, cột c nằm ở chỉ số 4*c + r.
    return bytes(
        state[4 * ((column + row) % 4) + row]
        for column in range(4) for row in range(4)
    )


def mix_columns(state):
    result = bytearray()
    for start in range(0, 16, 4):
        column = state[start:start + 4]
        for coefficients in MIX_MATRIX:
            value = 0
            for coefficient, byte in zip(coefficients, column, strict=True):
                value ^= gf_multiply(coefficient, byte)
            result.append(value)
    return bytes(result)


def encrypt(block, key, trace):
    if len(block) != 16 or len(key) != 16:
        raise ValueError("AES-128 cần bản rõ và khóa, mỗi giá trị đúng 16 byte.")
    trace("plaintext", block)
    trace("key", key)
    round_keys = expand_key(key, trace)
    state = xor_bytes(block, round_keys[0])
    trace("r.00.AddRoundKey", state)

    for number in range(1, 11):
        prefix = f"r.{number:02}"
        trace(f"{prefix}.input", state)
        trace(f"{prefix}.K", round_keys[number])
        state = state.translate(SBOX)
        trace(f"{prefix}.SubBytes", state)
        state = shift_rows(state)
        trace(f"{prefix}.ShiftRows", state)
        if number < 10:
            state = mix_columns(state)
            trace(f"{prefix}.MixColumns", state)
        state = xor_bytes(state, round_keys[number])
        trace(f"{prefix}.AddRoundKey", state)
    trace("ciphertext", state)
    return state
