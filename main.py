import os
import json
import time
import shutil
import base64
import ctypes
import hashlib
import secrets
import subprocess
from pathlib import Path
from ctypes import wintypes
from memoryeditor import MemoryEditor

MODULUS_BITS = 2048
MODULUS_BYTES = MODULUS_BITS // 8
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")
CRYPTPROTECT_UI_FORBIDDEN = 0x1
SMBIOS_UUID_COMMAND = "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID"
APP_DIR = Path(__file__).resolve().parent
EXE_FILE = APP_DIR / "lovelyspark.exe"
APP_DATA_DIR = Path(os.environ["APPDATA"]) / "lovelyspark"
LICENSE_FILE = APP_DATA_DIR / "license.json"
SETTINGS_FILE = APP_DATA_DIR / "update-settings.json"

PATTERNS = {
    "E8 ?? ?? ?? ?? 88 C3 C6 85 1F 03 00 00 01": "B8 01 00 00 00 88 C3 C6 85 1F 03 00 00 01",
    "31 C9 84 C0 41 BE 12 00 00 00 44 0F 44 F1 84 DB 44 0F 44 F1 48 83 7D 38 00 44 0F 45 F1": "31 C9 84 C0 41 BE 12 00 00 00 44 0F 44 F1 84 DB 44 0F 44 F1 48 83 7D 38 00 90 90 90 90"
}

class DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]

def read_smbios_uuid():
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", SMBIOS_UUID_COMMAND],
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()

def dpapi_encrypt(data):
    buffer = ctypes.create_string_buffer(data, len(data))
    source = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    target = DataBlob()

    ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source),
        None,
        None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(target),
    )
    return ctypes.string_at(target.pbData, target.cbData)

def patch_and_launch():
    p = subprocess.Popen([EXE_FILE], cwd=APP_DIR)

    me = MemoryEditor("lovelyspark.exe", verbose=False)
    me.attach_short(p.pid)
    seg = me.get_section_range_short(largest=True)

    blank = None
    while blank is None and p.poll() is None:
        blank = me.read_short(seg["tail"], 16)
        time.sleep(0.002)
    blank = blank or b""

    print("正在等待 Themida 解压负载！")
    if not any(blank):
        while p.poll() is None:
            d = me.read_short(seg["tail"], 16)
            if d and d != blank:
                break
            time.sleep(0.002)

    print("Themida 解压完成，开始 patch！")

    for pattern_hex, replacement_hex in PATTERNS.items():
        r = me.search_and_replace_short(
            pattern_hex,
            replacement_hex,
            base=seg["start"], size=seg["size"],
        )
        
    print("patch 完成！")

def disable_update():
    payload = {
        "manifestUrl": "http://127.0.0.1:9999/manifest.json", 
        "autoCheck": True
    }
    
    Path(SETTINGS_FILE).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print("更新已禁用！")

def create_license():
    if LICENSE_FILE.is_file():
        exp = json.loads(base64.b64decode(json.loads(LICENSE_FILE.read_text(encoding="utf-8"))["license"]))["expires_at"]
        if time.time() <= exp:
            print("现有许可证未过期，跳过许可证生成！")
            return
            
        shutil.rmtree(APP_DATA_DIR)
        
    license_data = {
        "qq":"10000",
        "nickname": "ReverseIsFun",
        "machine_code": base64.b64encode(dpapi_encrypt(read_smbios_uuid().encode("utf-8"))).decode("ascii"),
        "issued_at": 1761782400,
        "expires_at": 4102415999,
        "features": ["all"],
        "avatar": ""
    }

    modulus = secrets.randbits(MODULUS_BITS) | (1 << (MODULUS_BITS - 1)) | 1
    private_exponent = secrets.randbits(MODULUS_BITS) | (1 << (MODULUS_BITS - 1)) | 1
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(b"ReverseIsFun").digest()
    padding_length = MODULUS_BYTES - len(digest_info) - 3
    encoded_message = b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info
    signature_int = pow(int.from_bytes(encoded_message, "big"), private_exponent, modulus)
    signature = signature_int.to_bytes(MODULUS_BYTES, "big")
    
    payload = {
        "license": base64.b64encode(json.dumps(license_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii"),
        "signature": base64.b64encode(signature).decode()
    }
    
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    Path(LICENSE_FILE).write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print("许可证已生成！")

if __name__ == "__main__":
    if not EXE_FILE.is_file():
        raise RuntimeError("请在 lovelyspark 同目录运行此脚本。")
        
    create_license()
    disable_update()
    patch_and_launch()
    input("Enjoy reverse engineering!\n\nPress ENTER to exit...")
