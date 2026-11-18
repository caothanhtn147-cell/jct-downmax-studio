# JCT DownMax Studio (Clean-Room Sovereign Edition)
> **Thương hiệu:** JCT - Tiện Ích Giải Pháp Số  
> **Thư mục cài đặt:** `F:\JCT_DOWNMAX_STUDIO`

## 1. Khởi Chạy 1-Click (0% Cửa Sổ CMD Đen)
- Bấm đúp trực tiếp vào tệp **`JCT_DownMax_Studio.vbs`**.
- Giao diện web cục bộ tự động mở tại `http://127.0.0.1:8798/`.

## 2. Tính Năng Cốt Lõi
- **Đa nền tảng:** YouTube, TikTok, Facebook, Douyin và các trang web video chuẩn HTTPS.
- **Tự động nhận diện bộ đôi:** Tự tìm `yt-dlp.EXE` và `ffmpeg.exe` có sẵn trên Ổ F (tải 4K MP4, 1080p, Audio MP3).
- **Lõi SQLite WAL (Điều 201):** Chống trùng lặp hàng đợi, phục hồi job khi tắt ngang, giữ Ổ C luôn > 44 GB.
- **Bảo mật cấp Production:** Chống SSRF (chặn IP nội bộ/loopback), chống CSRF/DNS Rebinding (`Host`/`Origin` allowlist), 0% Emoji UI.

## 3. Kiểm Định Chất Lượng
Chạy toàn bộ bộ kiểm thử bằng lệnh:
```powershell
python F:\JCT_DOWNMAX_STUDIO\tests\test_core.py
python F:\JCT_DOWNMAX_STUDIO\tests\test_phase3_resilience.py
python F:\JCT_DOWNMAX_STUDIO\tests\test_phase4_api.py
```
