from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import os # Thêm thư viện os để kiểm tra file tồn tại

# Cấu hình đầu vào dữ liệu

# 1. Modulus (n) và Exponent (e) của khóa công khai CA (từ c1.pem)
file_n_hex = "module.txt" # Tệp chứa giá trị Modulus n ở dạng hex
e_int = 65537

# 2. Tên các file chứa chữ ký và phần thân chứng chỉ
file_signature_hex = "signature_final0.hex" # File chứa chữ ký ở dạng hex (từ Bước 3)
file_c0_body = "c0_body.bin" # File chứa phần thân chứng chỉ đã được ký (từ Bước 4)

# Chọn thuật toán mã hóa được sử dụng, vì đang sử dụng thuật toán mã hóa SHA256 nên chọn nó
chosen_hash_algorithm = hashes.SHA256()


# Kiểm tra sự tồn tại của các file đầu vào
if not os.path.exists(file_n_hex):
    print(f"Lỗi: Không tìm thấy tệp modulus '{file_n_hex}'.")
    exit()
if not os.path.exists(file_signature_hex):
    print(f"Lỗi: Không tìm thấy tệp chữ ký '{file_signature_hex}'. Vui lòng kiểm tra lại Bước 3.")
    exit()
if not os.path.exists(file_c0_body):
    print(f"Lỗi: Không tìm thấy tệp thân chứng chỉ '{file_c0_body}'. Vui lòng kiểm tra lại Bước 4.")
    exit()

# Đọc Modulus (n_hex) từ file
try:
    with open(file_n_hex, "r") as f_n:
        n_hex = f_n.read().strip() # Đọc và loại bỏ khoảng trắng/ký tự xuống dòng thừa
    if not n_hex:
        print(f"Lỗi: Tệp modulus '{file_n_hex}' trống.")
        exit()
except Exception as e:
    print(f"Lỗi khi đọc tệp modulus '{file_n_hex}': {e}")
    exit()

# Đọc chữ ký từ file và chuyển đổi
try:
    with open(file_signature_hex, "r") as f_sig:
        signature_hex_string = f_sig.read().strip()
    if not signature_hex_string:
        print(f"Lỗi: Tệp chữ ký '{file_signature_hex}' trống.")
        exit()
    signature_bytes = bytes.fromhex(signature_hex_string)
except ValueError:
    print(f"Lỗi: Nội dung trong tệp '{file_signature_hex}' không phải là chuỗi hex hợp lệ.")
    exit()
except Exception as e:
    print(f"Lỗi khi đọc hoặc chuyển đổi tệp chữ ký: {e}")
    exit()

# Đọc phần thân chứng chỉ (message_bytes) từ file
try:
    with open(file_c0_body, "rb") as f_body:
        message_bytes = f_body.read()
    if not message_bytes:
        print(f"Lỗi: Tệp thân chứng chỉ '{file_c0_body}' trống.")
        exit()
except Exception as e:
    print(f"Lỗi khi đọc tệp thân chứng chỉ: {e}")
    exit()

# Chuyển đổi n_hex (modulus) sang số nguyên
try:
    n_int = int(n_hex, 16)
except ValueError:
    # In ra một phần của n_hex để dễ debug nếu nó quá dài
    preview_n_hex = n_hex[:30] + "..." if len(n_hex) > 30 else n_hex
    print(f"Lỗi: Giá trị n_hex đọc từ '{file_n_hex}' ('{preview_n_hex}') không phải là chuỗi hex hợp lệ.")
    exit()

# Tạo đối tượng khóa công khai RSA từ n và e
try:
    public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
    public_key_ca = public_numbers.public_key()
except Exception as e:
    print(f"Lỗi khi tạo khóa công khai RSA từ n (đã chuyển đổi) và e={e_int}: {e}")
    exit()

# Tính toán và hiển thị hash của message_bytes (nội dung c0_body.bin)
try:
    digest = hashes.Hash(chosen_hash_algorithm) # Sử dụng thuật toán hash đã chọn
    digest.update(message_bytes)
    calculated_hash_bytes = digest.finalize()
    calculated_hash_hex = calculated_hash_bytes.hex()
    print(f"Giá trị băm của '{file_c0_body}' được tính bằng Python : {calculated_hash_hex}")
    print(f"(So sánh giá trị này với kết quả của lệnh '{chosen_hash_algorithm.name}sum {file_c0_body}')")
except Exception as e:
    print(f"Lỗi khi tính toán hash của '{file_c0_body}': {e}")

# Thực hiện xác minh chữ ký
# padding là PKCS1v15.
try:
    public_key_ca.verify(
        signature_bytes,
        message_bytes,          # Dữ liệu gốc đã được ký (nội dung của c0_body.bin)
        padding.PKCS1v15(),     # Sơ đồ đệm phổ biến cho chữ ký RSA
        chosen_hash_algorithm   # Thuật toán hash đã dùng. Phải khớp với chứng chỉ!
    )
    print(" Chữ ký HỢP LỆ! (Signature is VALID!) ") 
except InvalidSignature:
    print(" Chữ ký KHÔNG HỢP LỆ! (Signature is INVALID!) ") 
except Exception as e:
    print(f"Đã xảy ra lỗi trong quá trình xác minh: {e}")
