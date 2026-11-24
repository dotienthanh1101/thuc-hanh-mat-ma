"""Chạy test vector, in toàn bộ trạng thái và kiểm tra các mốc có đáp án."""

import argparse
import json
import re
from pathlib import Path

import aes128
import des

ROOT = Path(__file__).resolve().parent
ALGORITHMS = {"aes128": (aes128.encrypt, 16), "des": (des.encrypt, 8)}


def parse_hex(value, size):
    value = value.removeprefix("0x").removeprefix("0X")
    if not re.fullmatch(rf"[0-9a-fA-F]{{{size * 2}}}", value):
        raise ValueError(f"Giá trị phải có đúng {size * 2} ký tự hex.")
    return bytes.fromhex(value)


def run_vector(name, vector, save):
    encrypt, size = ALGORITHMS[vector["algorithm"]]
    block, key = (parse_hex(vector[field], size) for field in ("plaintext", "key"))
    states = {}

    def record(label, value, width=None):
        if isinstance(value, bytes):
            states[label] = value.hex().upper()
        else:
            states[label] = f"{value:0{width}X}"

    encrypt(block, key, record)
    lines = [f"Vector: {name}", f"Nguồn: {vector['source']}", "",
             "ks = lịch sinh khóa, r = trạng thái mã hóa. Mọi giá trị đều ở hệ hex.", ""]
    lines.extend(f"{label:24} {value}" for label, value in states.items())
    lines.extend(["", "Đối chiếu với giá trị kỳ vọng"])
    expected = vector["expected"]
    passed = 0
    for label, wanted in expected.items():
        actual = states.get(label)
        if actual == wanted.upper():
            lines.append(f"PASS {label:19} {actual}")
            passed += 1
        else:
            lines.append(f"FAIL {label:19} kỳ vọng {wanted}, thực tế {actual}")
    lines.append(f"Kết quả: {passed}/{len(expected)} mốc khớp.")
    report = "\n".join(lines) + "\n"
    print(report, end="")
    if save:
        directory = ROOT / "results"
        directory.mkdir(exist_ok=True)
        (directory / f"{name}.txt").write_text(report, encoding="utf-8")
    return passed == len(expected)


def main():
    vectors = json.loads((ROOT / "vectors.json").read_text(encoding="utf-8"))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vector", nargs="?", choices=vectors, help="Mặc định chạy tất cả.")
    parser.add_argument("--save", action="store_true", help="Ghi log vào thư mục results/.")
    args = parser.parse_args()
    names = [args.vector] if args.vector else list(vectors)
    results = [run_vector(name, vectors[name], args.save) for name in names]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
