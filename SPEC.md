# SPEC — JCT DOWNMAX STUDIO (CLEAN-ROOM SOVEREIGN SUITE)
> **Thương hiệu:** JCT - Tiện Ích Giải Pháp Số  
> **Vị trí cô lập:** `F:\JCT_DOWNMAX_STUDIO\` (0% xả rác Ổ C)  
> **Chuẩn mực:** 6 Khâu Titanium (Core-First -> Test-Verified -> Resilience -> UI/UX -> Codex Audit -> SSOT)

---

## 1. Mục Tiêu Sản Phẩm
Xây dựng công cụ tải & xử lý đa phương tiện đa nền tảng (YouTube, TikTok, Facebook, Douyin) chạy hoàn toàn **Local 100%**, miễn phí 0đ, **0% cửa sổ CMD đen**, lưu lịch sử và hàng đợi bằng **SQLite WAL**.

## 2. Lộ Trình 6 Khâu Triển Khai
1. **Khâu 1 (SPEC & Kiến trúc):** Chốt cấu trúc module, schema SQLite WAL, hợp đồng đầu vào/đầu ra. *(Đang hoàn thành)*
2. **Khâu 2 (Lõi Thép - Core Engine):** Xây dựng `db_vault.py` + `media_engine.py` + chạy 100% Unit Test (`tests/test_core.py`). *(Triển khai ngay)*
3. **Khâu 3 (Sức Bền & RAII):** Watchdog dọn tiến trình con, Circuit Breaker, chống trùng lặp URL, quản lý Proxy an toàn.
4. **Khâu 4 (UI/UX & 1-Click Launcher):** Giao diện desktop/web cục bộ theo Design Tokens (0% Emoji nút bấm) + Launcher `.vbs` (`pythonw.exe`).
5. **Khâu 5 (Tổng Audit Liên Mô Hình):** Codex GPT (`gpt-6.1-sol`) Red-Team Audit + Nghiệm thu UI thật (Điều 207).
6. **Khâu 6 (Đóng Gói & Git SSOT):** Tài liệu hướng dẫn sử dụng + Commit vào kho lưu trữ chuẩn.

## 3. Hợp Đồng Dữ Liệu (SQLite WAL Schema)
Bảng `jobs`:
- `id` (INTEGER PRIMARY KEY AUTOINCREMENT)
- `url` (TEXT NOT NULL)
- `platform` (TEXT NOT NULL) — `youtube | tiktok | facebook | douyin | generic`
- `title` (TEXT)
- `quality` (TEXT DEFAULT 'best')
- `output_dir` (TEXT NOT NULL)
- `output_path` (TEXT)
- `status` (TEXT NOT NULL DEFAULT 'queued') — `queued | probing | downloading | completed | failed | cancelled`
- `error_msg` (TEXT)
- `created_at` (TEXT NOT NULL)
- `updated_at` (TEXT NOT NULL)
