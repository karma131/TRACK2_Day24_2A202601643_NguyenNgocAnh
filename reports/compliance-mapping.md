# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Dữ liệu chủ thể nằm trong kho JSON tách biệt; ledger chỉ lưu hash của tham số, không sao chép PII, nên có thể xoá record mà vẫn giữ bằng chứng xử lý. | `data/customers.json`; `agent/runner.py:79-91`; `agent/ledger.py:49-68` |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Egress của dữ liệu restricted mặc định bị từ chối và mọi quyết định có dấu vết kiểm toán. Khi bật model ngoài lab phải lập hồ sơ/đánh giá chuyển dữ liệu trước khi cho phép. | `agent/policy.py:49-50`; `agent/runner.py:122-127`; `reports/ledger.jsonl` |
| ASI03 — privilege abuse | PEP kiểm tra classification, purpose, owner, delegation depth và egress trước khi gọi tool; cả allow/deny đều có reason. | `agent/policy.py:39-55`; `agent/runner.py:73-91` |
| ASI01 — goal hijack | Trifecta split ngăn free text không tin cậy quyết định customer ID; Run B chỉ nhận ticket ID lấy từ tên file và ánh xạ qua nguồn tin cậy. | `agent/runner.py:93-119`; `tests/test_split.py` |
| ISO 42001 Clause 5-6 | Trách nhiệm theo owner/run ID, policy có mục đích xử lý, kiểm soát rủi ro và ledger hash-chain tạo bằng chứng quản trị. | `agent/runner.py:69-91`; `agent/ledger.py:38-93`; `reports/dpia-lite.md` |
