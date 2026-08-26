# DPIA-lite (1 trang)

## 1. Dữ liệu gì

`search_docs` đọc ticket hỗ trợ, có thể chứa mã khách hàng và PII do người
dùng tự nhập. Trước khi nội dung đi vào context, `pii.redact` phát hiện và
che CCCD, số điện thoại, số tài khoản ngân hàng và email. `read_customer`
đọc kho restricted gồm mã khách, họ tên, CCCD, SĐT, STK, email và danh sách
ticket liên quan. Ledger chỉ lưu metadata và SHA-256 của arguments, không
lưu arguments hay bản ghi khách hàng nguyên văn.

## 2. Mục đích gì

Mục đích là tổng hợp và hỗ trợ xử lý ticket. Run A tìm tài liệu để tạo bản
tóm tắt. Run B chỉ đọc khách hàng có quan hệ đã được khai báo với ticket ID
hợp lệ, phục vụ phản hồi hỗ trợ; dữ liệu không được dùng theo customer ID
nằm trong nội dung tự do. Mỗi tool call mang `request_purpose` và
`agent_owner` để policy quyết định và quy trách nhiệm.

## 3. Chảy đi đâu

Trong đường mặc định `--mock`, dữ liệu chỉ nằm trong repo và bộ nhớ tiến
trình. Local sink `localhost:9999` là đích mô phỏng exfil, nhưng PEP từ
chối mọi lần restricted data đi qua run có egress; `attack-after.log`
chứng minh sink rỗng. Ledger nội bộ nhận metadata audit có hash-chain.

Nếu dùng `--model`, nội dung tóm tắt có thể đi tới API của nhà cung cấp ở
nước ngoài và được xem là luồng xuyên biên giới. Trước khi bật cần có căn
cứ pháp lý, hồ sơ/đánh giá theo NĐ 356/2025, thời hạn lưu giữ và quy trình
xoá phù hợp; không dùng đường này mặc định. PII redaction giảm dữ liệu gửi
đi, còn policy tại `agent/policy.py` chặn restricted + egress khi chưa có
ủy quyền phù hợp.
