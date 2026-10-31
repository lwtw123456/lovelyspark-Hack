import os
import json
import time
import shutil
import base64
import ctypes
import subprocess
from pathlib import Path
from ctypes import wintypes
from memoryeditor import MemoryEditor

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
    print("已禁用更新！")

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
    
    payload = {
        "license": base64.b64encode(json.dumps(license_data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).decode("ascii"),
        "signature": "OvCibovWLwrLyjR6XLKPfIDN/RXJloweB2usDWnRZAV6jOz3kHo1oB3VAHkIbzkpe0tVHwiKEL+ZUtoqlowkippykhoMAiWGmZGAgZm0kzWzS0GtL0cazIUJDijIl4URFBGgkRu8YThmXpEP8spRbnTFEilfQexVBMTTXbPD32c2h/74VYxOmiqy2Ey1IZv+32dYMINmth2KwI3sNYO+GiwmkoVHaUx3raspBXxjEFD2HU5kO8jKbeiuQ1VVftoe5uDH9InSS7MM2Msj7IebRmIo+IQHGMmG5ZaDZre1BloYAWRa3gCNMxrH5TcATIHPkA1A9m4GNRjj/01zDHExSA=="
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