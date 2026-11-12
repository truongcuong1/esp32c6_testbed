import sys
import serial
import subprocess
import argparse

def main():
    parser = argparse.ArgumentParser(description="Bridge USB PCAP stream to Wireshark and File")
    parser.add_argument("--port", required=True, help="COM Port (e.g. COM3 or /dev/ttyACM0)")
    parser.add_argument("--out", default=None, help="Tên file PCAP cần lưu (vd: node_a.pcap)")
    args = parser.parse_args()

    print(f"[*] Dang ket noi cong {args.port}...")
    ser = serial.Serial(args.port, 115200, timeout=1)

    out_file = open(args.out, "wb") if args.out else None
    cmd = [r"C:\Program Files\Wireshark\Wireshark.exe", "-k", "-i", "-"]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)

    print(f"[*] Wireshark da khoi dong. Dang stream du lieu tu {args.port}...")
    try:
        while True:
            data = ser.read(1024)
            if data:
                proc.stdin.write(data)
                proc.stdin.flush()
                if out_file:
                    out_file.write(data)
                    out_file.flush()
    except KeyboardInterrupt:
        print("\n[*] Dung capture.")
    finally:
        ser.close()
        proc.stdin.close()
        if out_file:
            out_file.close()
        proc.wait()

if __name__ == "__main__":
    main()