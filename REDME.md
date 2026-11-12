
pip install pyserial scapy ( Cài đặt thư viện Python )
python tools/pcap_bridge.py --port COM10 --out node_a.pcap
python tools/pcap_bridge.py --port COM13 --out node_b.pcap
python tools/pcap_bridge.py --port COM14 --out node_c.pcap

------------------------------------------------------------------------------

Sửa lỗi xung đột Target ngay trên Terminal này
Ngay tại cửa sổ PowerShell hiện tại, bạn chạy 2 lệnh sau:
Xóa biến môi trường đang gán nhầm:
PowerShell
Remove-Item Env:\IDF_TARGET
(Nếu đang ở CMD thường thì gõ: set IDF_TARGET= rồi bấm Enter).
Chạy lại lệnh set target:
PowerShell espidf terminal
    idf.py set-target esp32c6
Dấu hiệu thành công: Terminal sẽ hiện dòng chữ màu xanh hoặc vàng tạo file sdkconfig mới mà không còn dòng đỏ báo "not consistent" nữa.

--------------------------------------------------------------------------------

Đúng rồi, đó là cách ghi đè hoặc đặt trực tiếp biến môi trường IDF_TARGET trong phiên dòng lệnh để ép hệ thống hiểu ngay con chip bạn đang dùng mà không cần mở giao diện.
Tùy vào cửa sổ dòng lệnh bạn đang mở, các lệnh thực hiện như sau:
1. Nếu đang dùng PowerShell (VS Code mặc định hay mở cái này)
Chạy lần lượt 2 dòng sau:
PowerShell
Remove-Item Env:\IDF_TARGET -ErrorAction SilentlyContinue
    $env:IDF_TARGET="esp32c6"
Dấu hiệu nhận biết: Sau khi gán, gõ $env:IDF_TARGET rồi Enter, màn hình in ra đúng chữ esp32c6.
2. Nếu đang dùng Command Prompt (CMD)
Gõ lệnh xóa rồi gán lại trên cùng một dòng:
DOS
    set IDF_TARGET= && set IDF_TARGET=esp32c6
Dấu hiệu nhận biết: Gõ echo %IDF_TARGET% rồi Enter, màn hình in ra đúng chữ esp32c6


---------------------------------------------------------------------------
PHẦN 4: Lấy số liệu tự động chỉ bằng 1 câu lệnh (Không cần đếm tay)
Bạn không cần ngồi đếm từng gói hay tính toán thủ công. Script Python bạn đã tạo sẵn sẽ làm việc này thay bạn.
Mở một cửa sổ Terminal tại thư mục esp32c6_testbed, gõ:
Bash
    python tools/verify_ground_truth.py node_a.pcap node_b.pcap node_c.pcap
Nó sẽ quét cả 3 file và in ra một bản báo cáo tự động gồm:
    Tổng số gói tin Node A gửi và Node B nhận.
    Tỷ lệ mất gói (Packet Loss %).
    Độ trễ trung bình L2-L2 (ms).
    Xác nhận khớp dữ liệu 100%.
    Bạn chỉ việc chụp ảnh màn hình bảng kết quả đó dán thẳng vào slide báo cáo là hoàn thành bài thí nghiệm!