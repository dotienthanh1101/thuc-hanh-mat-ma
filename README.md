# Thực hành mật mã · DES và AES-128

Sinh viên **Đỗ Tiến Thành**. Chương trình thực hiện mã hóa một khối bằng Python 3.10 trở lên. Các phép toán được cài đặt trực tiếp bằng thao tác bit và byte. OpenSSL chỉ dùng để đối chiếu bản mã khi kiểm tra.

## Chạy chương trình

```text
python run_vectors.py
python run_vectors.py --save
python run_vectors.py aes-tuan-11
python run_vectors.py des-tham-chieu
```

Lệnh đầu in cả ba vector ra terminal. Thêm `--save` để ghi lại các log trong `results/`. Mã thoát là 1 nếu một mốc có đáp án bị sai. Có thể thêm vector vào `vectors.json` theo cấu trúc sẵn có. Với DES, mỗi bản rõ và khóa có 16 ký tự hex. Với AES-128, mỗi giá trị có 32 ký tự hex. Đặt các mốc đã biết trong `expected` bằng đúng nhãn dùng trong log.

| Vector | Nguồn | Kết quả nổi bật |
| --- | --- | --- |
| [AES tuần 11](results/aes-tuan-11.txt) | Đề bài cho P = 0x11 và K = 0x00 dưới dạng viết rút gọn. Thêm byte 00 bên trái cho đủ 128 bit. | K₁ = `62636363626363636263636362636363`, state cuối vòng 1 = `E0E138D9010000000100000001000000`, bản mã = `0410BEFCCDE6944B69DD007DEBE39A9D`. |
| [AES tham chiếu](results/aes-fips197.txt) | FIPS 197, bản 2001, Phụ lục C.1 | Bản mã = `69C4E0D86A7B0430D8CDB78070B4C55A`. |
| [DES tham chiếu](results/des-tham-chieu.txt) | Ví dụ công khai của Lund University. Đang chờ dữ liệu DES trên bảng để chạy đúng vector của lớp. | K₁ = `1B02EFFC7072`, L₁ = `F0AAF0AA`, R₁ = `EF4A6544`, bản mã = `85E813540F0AB405`. |

`vectors.json` lưu các mốc kỳ vọng từ bài tính tay và tài liệu tham chiếu. Bản mã của AES tuần 11 được đối chiếu độc lập bằng OpenSSL. Nhãn PASS chỉ áp dụng cho các mốc có đáp án trong mục Đối chiếu. Phần trên của mỗi log là toàn bộ giá trị chương trình sinh ra.

## DES ([des.py](des.py) và [des_tables.py](des_tables.py))

1. PC-1 lấy 56 bit của khóa 64 bit, bỏ 8 bit chẵn lẻ và chia thành C₀, D₀ (mỗi nửa 28 bit). Tại vòng i, dịch vòng trái hai nửa theo lịch `SHIFTS`. PC-2 chọn 48 bit để được Kᵢ.
2. IP hoán vị khối bản rõ rồi tách thành L₀, R₀. Trong mỗi vòng, E mở rộng Rᵢ₋₁ từ 32 lên 48 bit rồi XOR với Kᵢ. Chia kết quả thành tám nhóm 6 bit. Hai bit ngoài xác định hàng, bốn bit giữa xác định cột S-box. Ghép tám kết quả 4 bit rồi hoán vị P.
3. Gán Lᵢ = Rᵢ₋₁ và Rᵢ = Lᵢ₋₁ XOR đầu ra của P. Sau vòng 16, đổi thứ tự hai nửa thành R₁₆ ‖ L₁₆ rồi áp dụng FP.
4. Trong log, `ks.01.K` là khóa vòng 1. `r.01.E_xor_K` là giá trị trước khi chia nhóm cho các S-box. `r.01.P` là đầu ra hàm Feistel và `r.01.L`, `r.01.R` là hai nửa sau vòng 1.

## AES-128 ([aes128.py](aes128.py))

1. State chứa 16 byte, đọc theo cột. Byte ở hàng r, cột c nằm ở vị trí 4c + r, tính từ 0. Mỗi nhóm 8 ký tự hex trong log là một cột.
2. Chia K₀ thành bốn từ 32 bit. Ở đầu mỗi vòng sinh khóa, áp dụng RotWord, SubWord và XOR với Rcon lên từ trước đó. XOR kết quả với từ cách 4 vị trí để tạo từ mới. Ba từ còn lại của mỗi khóa con được tạo bằng quy tắc wᵢ = wᵢ₋₄ XOR wᵢ₋₁.
3. Vòng 0 chỉ có AddRoundKey với K₀. Vòng 1 đến 9 lần lượt thực hiện SubBytes, ShiftRows, MixColumns và AddRoundKey. Vòng 10 thực hiện SubBytes, ShiftRows và AddRoundKey.
4. S-box tính bằng nghịch đảo trong GF(2⁸) rồi biến đổi affine. MixColumns nhân ma trận cố định với từng cột trong cùng trường. Trong log, `r.01.K` là khóa con và `r.01.AddRoundKey` là state đầu ra vòng 1.

## Nguồn tham chiếu

- [NIST FIPS 46-3, Data Encryption Standard](https://csrc.nist.gov/pubs/fips/46-3/final)
- [Lund University, Project 4: Learning about DES](https://www.eit.lth.se/fileadmin/eit/courses/edin01/project_des.pdf)
- [NIST FIPS 197, Advanced Encryption Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
