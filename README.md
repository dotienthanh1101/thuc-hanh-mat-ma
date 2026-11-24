# Thực hành mật mã · DES và AES-128

Sinh viên **Đỗ Tiến Thành**. Chương trình thực hiện mã hóa một khối bằng Python 3.10 trở lên. Các phép toán được cài đặt trực tiếp bằng thao tác bit và byte. OpenSSL chỉ dùng để đối chiếu bản mã khi kiểm tra.

## Chạy chương trình

```text
python run_vectors.py
python run_vectors.py --save
python run_vectors.py aes-tuan-11
python run_vectors.py des-tham-chieu
python run_vectors.py des-sbox-bai-ghi
python run_vectors.py aes-bai-ghi-1111
```

Lệnh đầu in cả năm vector ra terminal. Thêm `--save` để ghi lại các log trong `results/`. Mã thoát là 1 nếu một mốc có đáp án bị sai. Có thể thêm vector vào `vectors.json` theo cấu trúc sẵn có. Với DES, mỗi bản rõ và khóa có 16 ký tự hex. Với AES-128, mỗi giá trị có 32 ký tự hex. Đặt các mốc đã biết trong `expected` bằng đúng nhãn dùng trong log.

## Kết quả chạy

### AES-128 tuần 11

Bản rõ kết thúc bằng `00 11`, khóa toàn `00`. Các giá trị AES bên dưới đọc theo cột.

- Khóa con vòng 1  
  `62636363 62636363 62636363 62636363`
- Trạng thái cuối vòng 1  
  `E0E138D9 01000000 01000000 01000000`
- Bản mã  
  `0410BEFC CDE6944B 69DD007D EBE39A9D`

[Xem log AES-128 tuần 11](results/aes-tuan-11.txt)

### DES — Ví dụ tra S-box

Cặp bản rõ và khóa được chọn để vòng 1 đưa `010111` vào S₁, tương ứng với hàng 1, cột 11 trong vở. S₁ cho đầu ra `B` (hex).

- Bản rõ `0000000000000000`
- Khóa `B0B0B0B0B0B0B0B0`
- Bản mã `320CD08D36E0EDFB`

[Xem log DES](results/des-sbox-bai-ghi.txt)

### Kiểm tra bổ sung

- **AES-128 theo bài ghi** dùng bản rõ kết thúc bằng `11 11`. Trạng thái cuối vòng 1 là `E0E138D9 E038D9E1 01000000 01000000`. Bản mã là `442758DF 6DDA9EDB 6BF1468A 17B93FE5`. [Xem log](results/aes-bai-ghi-1111.txt)
- **AES-128 theo FIPS 197, Phụ lục C.1** cho bản mã `69C4E0D8 6A7B0430 D8CDB780 70B4C55A`. [Xem log](results/aes-fips197.txt)
- **DES theo ví dụ của Lund University** cho khóa con vòng 1 `1B02EFFC7072`, hai nửa sau vòng 1 `F0AAF0AA` và `EF4A6544`, bản mã `85E813540F0AB405`. [Xem log](results/des-tham-chieu.txt)

**Kết quả kiểm định** · 35/35 mốc khớp. `vectors.json` lưu giá trị kỳ vọng từ bài tính tay, tài liệu tham chiếu và phép đối chiếu bản mã. Bản mã của cả năm vector đã được đối chiếu độc lập bằng OpenSSL. Nhãn PASS chỉ áp dụng cho các mốc có đáp án trong mục Đối chiếu. Phần trên của mỗi log là toàn bộ giá trị chương trình sinh ra.

## DES ([des.py](des.py) và [des_tables.py](des_tables.py))

1. PC-1 lấy 56 bit của khóa 64 bit, bỏ 8 bit chẵn lẻ và chia thành C₀, D₀ (mỗi nửa 28 bit). Tại vòng i, dịch vòng trái hai nửa theo lịch `SHIFTS`. PC-2 chọn 48 bit để được Kᵢ.
2. IP hoán vị khối bản rõ rồi tách thành L₀, R₀. Trong mỗi vòng, E mở rộng Rᵢ₋₁ từ 32 lên 48 bit rồi XOR với Kᵢ. Chia kết quả thành tám nhóm 6 bit. Hai bit ngoài xác định hàng, bốn bit giữa xác định cột S-box. Ghép tám kết quả 4 bit rồi hoán vị P.
3. Gán Lᵢ = Rᵢ₋₁ và Rᵢ = Lᵢ₋₁ XOR đầu ra của P. Sau vòng 16, đổi thứ tự hai nửa thành R₁₆ ‖ L₁₆ rồi áp dụng FP.
4. Trong log, `ks.01.K` là khóa vòng 1. `r.01.E_xor_K` là giá trị trước khi chia nhóm cho các S-box. `r.01.P` là đầu ra hàm Feistel và `r.01.L`, `r.01.R` là hai nửa sau vòng 1.

Vở ghi cung cấp hàng `01` và cột `1011` ở nhóm S₁. Ghép hai bit ngoài với bốn bit giữa được `0 1011 1`, tức `0x17`. Với P toàn bit 0 thì IP và E(R₀) đều bằng 0. Chọn K = `B0B0B0B0B0B0B0B0` để sáu bit đầu của K₁ là `010111`. Vì vậy S₁ nhận đúng nhóm đó sau XOR và cho `1011` (hex `B`). Cặp P, K do người triển khai chọn để kiểm định ví dụ tra bảng. Vở ghi chỉ cung cấp bước tra S-box.

## AES-128 ([aes128.py](aes128.py))

1. State chứa 16 byte, đọc theo cột. Byte ở hàng r, cột c nằm ở vị trí 4c + r, tính từ 0. Mỗi nhóm 8 ký tự hex trong log là một cột.
2. Chia K₀ thành bốn từ 32 bit. Ở đầu mỗi vòng sinh khóa, áp dụng RotWord, SubWord và XOR với Rcon lên từ trước đó. XOR kết quả với từ cách 4 vị trí để tạo từ mới. Ba từ còn lại của mỗi khóa con được tạo bằng quy tắc wᵢ = wᵢ₋₄ XOR wᵢ₋₁.
3. Vòng 0 chỉ có AddRoundKey với K₀. Vòng 1 đến 9 lần lượt thực hiện SubBytes, ShiftRows, MixColumns và AddRoundKey. Vòng 10 thực hiện SubBytes, ShiftRows và AddRoundKey.
4. S-box tính bằng nghịch đảo trong GF(2⁸) rồi biến đổi affine. MixColumns nhân ma trận cố định với từng cột trong cùng trường. Trong log, `r.01.K` là khóa con và `r.01.AddRoundKey` là state đầu ra vòng 1.

## Nguồn tham chiếu

- [NIST FIPS 46-3, Data Encryption Standard](https://csrc.nist.gov/pubs/fips/46-3/final)
- [Lund University, Project 4: Learning about DES](https://www.eit.lth.se/fileadmin/eit/courses/edin01/project_des.pdf)
- [NIST FIPS 197, Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
