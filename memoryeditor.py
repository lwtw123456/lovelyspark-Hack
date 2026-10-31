import threading
from contextlib import contextmanager
from win_api import *
import logging
import time
import struct
import os

import pymem.exception
import pymem
import pymem.process


class MemoryEditor:
    """内存编辑器类"""
    def __init__(self, process_name, verbose=True):
        self.process_name = process_name
        self.pm = None
        self.base_module_info = None
        self._lock_threads = {}
        self._lock_counter = 0
        self._lock_threads_lock = threading.Lock()
        self._short_pid = None
        self._suspended = {}
        self.logger = logging.getLogger(f"MemoryEditor.{process_name}")
        
        if verbose:
            if not self.logger.handlers:
                handler = logging.StreamHandler()
                formatter = logging.Formatter('[%(levelname)s] %(message)s')
                handler.setFormatter(formatter)
                self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        else:
            if not self.logger.handlers:
                self.logger.addHandler(logging.NullHandler())
            self.logger.setLevel(logging.CRITICAL + 1)

    def connect(self):
        """连接到进程（解析出 PID 后交给 connect_by_pid，打开流程只有一份）"""
        pid = self.find_pid()
        if not pid:
            self.logger.error(f"错误: 未找到 {self.process_name} 进程")
            return None
        return self.connect_by_pid(pid)
    
    def connect_by_pid(self, pid):
        """通过 PID 连接进程"""
        try:
            self.pm = pymem.Pymem()
            self.pm.open_process_from_id(pid)

            self.base_module_info = self.get_module_base_address()

            if not self.base_module_info:
                self.logger.error("错误: 无法获取主模块信息")
                self.pm.close_process()
                self.pm = None
                return None

            self.logger.info(
                f"已连接进程 PID={pid}, "
                f"主模块={self.base_module_info['name']}, "
                f"基址=0x{self.base_module_info['base']:X}, "
                f"大小=0x{self.base_module_info['size']:X}"
            )

            return self.pm

        except Exception as e:
            self.logger.error(f"通过 PID 连接进程失败: {e}")

            if self.pm:
                try:
                    self.pm.close_process()
                except Exception:
                    pass

            self.pm = None
            self.base_module_info = None

            return None
    
    def disconnect(self):
        """断开连接"""
        self.unlock_all()
        
        if self.pm:
            try:
                self.pm.close_process()
                self.logger.info(f"已断开与 {self.process_name} 的连接")
            finally:
                self.pm = None
                self.base_module_info = None

    def attach_short(self, pid=None, retries=500, delay=0.02):
        """短连接：只记录 PID，不开长期句柄；等到主模块可用再返回"""
        if pid is None:
            for _ in range(retries):
                pid = self.find_pid()
                if pid:
                    break
                time.sleep(delay)
        if not pid:
            self.logger.error("短连接失败: 未找到进程")
            return False

        self._short_pid = pid
        for _ in range(retries):
            if self.get_base_short():
                self.logger.info(f"短连接就绪 PID={pid}")
                return True
            time.sleep(delay)

        self.logger.error(f"短连接失败: PID={pid} 主模块不可用")
        self._short_pid = None
        return False

    def detach_short(self):
        """释放短连接：先松开还挂着的线程，再清 PID（全程不持有句柄）"""
        if self._suspended:
            self.resume_all_threads()
        self._short_pid = None

    def find_pid(self, name=None):
        """按映像名查 PID，全程只用瞬开瞬关的查询句柄"""
        target = (name or self.process_name).lower()
        arr = (wintypes.DWORD * 8192)()
        need = wintypes.DWORD()
        if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(need)):
            return None

        count = need.value // ctypes.sizeof(wintypes.DWORD)
        buf = ctypes.create_unicode_buffer(MAX_MODULE_NAME_LENGTH)
        for i in range(count):
            pid = arr[i]
            if not pid:
                continue
            h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not h:
                continue
            try:
                length = wintypes.DWORD(MAX_MODULE_NAME_LENGTH)
                if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(length)):
                    if os.path.basename(buf.value).lower() == target:
                        return pid
            finally:
                kernel32.CloseHandle(h)
        return None

    def get_thread_ids(self, pid=None):
        """短连接列出目标进程所有线程 TID（快照用完即关）"""
        pid = pid or self._short_pid
        if not pid:
            return []

        snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        if not snap or snap == INVALID_HANDLE_VALUE:
            return []
        try:
            te = THREADENTRY32()
            te.dwSize = ctypes.sizeof(THREADENTRY32)
            tids = []
            if kernel32.Thread32First(snap, ctypes.byref(te)):
                while True:
                    if te.th32OwnerProcessID == pid:
                        tids.append(te.th32ThreadID)
                    te.dwSize = ctypes.sizeof(THREADENTRY32)
                    if not kernel32.Thread32Next(snap, ctypes.byref(te)):
                        break
            return tids
        finally:
            kernel32.CloseHandle(snap)

    def suspend_all_threads(self):
        """挂起目标进程所有线程，返回 {tid: 挂起前计数}；一个都没挂上返回 {}

        仍然是短连接：每个线程 OpenThread → SuspendThread → CloseHandle 一气呵成，
        只把自己挂了几次记在 _suspended 里，恢复时重新开句柄。
        注意线程在内核态时只是打了标记，回到用户态才真正停下。
        """
        tids = self.get_thread_ids()
        if not tids:
            self.logger.error("挂起失败: 未找到目标进程的线程")
            return {}

        prev_counts = {}
        for tid in tids:
            h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
            if not h:
                continue          # 线程刚退出或权限不足，跳过
            try:
                prev = kernel32.SuspendThread(h)
            finally:
                kernel32.CloseHandle(h)

            if prev == 0xFFFFFFFF:
                continue
            prev_counts[tid] = prev
            self._suspended[tid] = self._suspended.get(tid, 0) + 1

        if prev_counts:
            self.logger.info(f"已挂起 {len(prev_counts)}/{len(tids)} 个线程: "
                             f"{sorted(prev_counts)}")
        else:
            self.logger.error("挂起失败: 所有线程都无法打开")
        return prev_counts

    def resume_all_threads(self):
        """松开本工具对目标进程所有线程的挂起，返回成功恢复的线程数

        只按自己挂起的次数还原，不会把别人的挂起也放掉。
        """
        if not self._suspended:
            return 0

        done = 0
        for tid, count in list(self._suspended.items()):
            h = kernel32.OpenThread(THREAD_SUSPEND_RESUME, False, tid)
            if not h:
                del self._suspended[tid]      # 线程已退出，没什么可恢复的
                continue
            try:
                for _ in range(count):
                    if kernel32.ResumeThread(h) == 0xFFFFFFFF:
                        break
                    self._suspended[tid] -= 1
            finally:
                kernel32.CloseHandle(h)

            if self._suspended.get(tid, 0) <= 0:
                del self._suspended[tid]
                done += 1

        self.logger.info(f"已松开 {done} 个线程")
        return done

    @contextmanager
    def _short_handle(self, access=None):
        if self._short_pid is None:
            raise RuntimeError("未建立短连接，请先调用 attach_short()")
        h = kernel32.OpenProcess(access or PROCESS_VM_READ, False, self._short_pid)
        if not h:
            raise OSError(ctypes.get_last_error(), "OpenProcess 失败")
        try:
            yield h
        finally:
            kernel32.CloseHandle(h)

    @staticmethod
    def _read_mem(handle, address, size):
        """用已有句柄读内存，失败返回 None"""
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if not kernel32.ReadProcessMemory(
            handle, ctypes.c_void_p(address), buf, size, ctypes.byref(got)
        ):
            return None
        return buf.raw[:got.value]

    @staticmethod
    def _write_mem(handle, address, data):
        """用已有句柄写内存：临时放开写权限，写完立刻恢复原保护"""
        length = len(data)
        if not length:
            return False

        old_protect = wintypes.DWORD()
        if not kernel32.VirtualProtectEx(
            handle, ctypes.c_void_p(address), length,
            PAGE_EXECUTE_READWRITE, ctypes.byref(old_protect)
        ):
            return False

        try:
            written = ctypes.c_size_t(0)
            ok = kernel32.WriteProcessMemory(
                handle, ctypes.c_void_p(address), ctypes.c_char_p(data),
                length, ctypes.byref(written)
            )
        finally:
            kernel32.VirtualProtectEx(
                handle, ctypes.c_void_p(address), length,
                old_protect.value, ctypes.byref(wintypes.DWORD())
            )

        return bool(ok) and written.value == length

    def _write_verified(self, handle, address, data, original=None):
        """读原值 → 写（必要时改保护并立刻还原）→ 回读校验

        long 版传 self.pm.process_handle，short 版传瞬开瞬关的句柄，
        写入校验逻辑只有这一份。返回 {'success','address','original','new'}。
        """
        result = {'success': False, 'address': address, 'original': '', 'new': ''}
        length = len(data)
        if length == 0:
            self.logger.error("✗ 替换字节为空")
            return result

        if original is None:
            original = self._read_mem(handle, address, length)
            if original is None:
                self.logger.error(f"✗ 读取原始字节失败 0x{address:X}")
                return result

        result['original'] = original.hex(' ').upper()
        self.logger.info(f"原始字节: {result['original']}")

        if not self._write_mem(handle, address, data):
            self.logger.error(f"✗ 写入失败 0x{address:X}")
            return result

        new = self._read_mem(handle, address, length)
        result['new'] = new.hex(' ').upper() if new else ''
        result['success'] = new == data
        if not result['success']:
            self.logger.error(f"✗ 校验失败，当前字节: {result['new']}")
        return result

    def _log_replace_header(self, address, display, length, type_name=None):
        """替换前的统一日志头"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"替换地址: 0x{address:X}")
        self.logger.info(f"替换字节: {display}")
        self.logger.info(f"字节长度: {length}")
        if type_name:
            self.logger.info(f"参数类型: {type_name}")
        self.logger.info(f"{'='*60}")

    def _replace_targets(self, targets, replacement, writer):
        """统一的替换循环与结果统计（long / short 共用）

        targets: [(address, extra_dict)]，extra_dict 只用于日志和结果附加字段
        writer:  (address, data) -> {'success','original','new'}
        """
        result = {'success_count': 0, 'data': [], 'errors': []}
        total = len(targets)

        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"总共找到 {total} 个匹配项，开始替换...")
        self.logger.info(f"{'='*60}")

        for i, (addr, extra) in enumerate(targets):
            self.logger.info(f"\n[{i + 1}/{total}] 地址: 0x{addr:X}")
            for key, value in extra.items():
                shown = f"0x{value:X}" if isinstance(value, int) else str(value)
                self.logger.info(f"  {key}: {shown}")

            try:
                replaced = writer(addr, replacement)
            except Exception as e:
                error_msg = f"替换异常: 地址 0x{addr:X}, 错误: {e}"
                result['errors'].append(error_msg)
                self.logger.error(f"  ✗ {error_msg}")
                continue

            if replaced.get('success'):
                result['success_count'] += 1
                entry = {'address': addr}
                entry.update(extra)
                entry['original'] = replaced['original']
                entry['new'] = replaced['new']
                result['data'].append(entry)
                self.logger.info("  ✓ 替换成功!")
            else:
                error_msg = f"替换失败: 地址 0x{addr:X}"
                result['errors'].append(error_msg)
                self.logger.error(f"  ✗ {error_msg}")

        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"替换完成! 成功: {result['success_count']}/{total}")
        if result['errors']:
            self.logger.error(f"失败: {len(result['errors'])}")
        self.logger.info(f"{'='*60}")

        return result

    def _log_scan_header(self, pattern_hex, pattern_length,
                         user_only=True, base_only=False, replacement_display=None):
        """搜索头 + 扫描范围日志（search / search_and_replace 共用）"""
        self.logger.info(f"\n{'='*60}")
        self.logger.info(f"搜索特征码: {pattern_hex}")
        if replacement_display is not None:
            self.logger.info(f"替换为:     {replacement_display}")
        self.logger.info(f"模式长度:   {pattern_length} 字节")

        if base_only:
            if self.base_module_info:
                self.logger.info(f"扫描范围:   基础模块 "
                                 f"({self.process_name}, "
                                 f"0x{self.base_module_info['base']:X})")
            else:
                self.logger.info("扫描范围:   基础模块 (未找到模块信息)")
        else:
            self.logger.info(f"扫描范围:   {'仅用户模块' if user_only else '所有模块'}")

        self.logger.info(f"{'='*60}")

    def read_short(self, address, size):
        """短连接读内存，失败返回 None"""
        try:
            with self._short_handle() as h:
                return self._read_mem(h, address, size)
        except OSError:
            return None

    def get_base_short(self):
        """短连接取主模块信息，复用 get_module_base_address / enum_modules_manual"""
        try:
            with self._short_handle(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as h:
                info = self.get_module_base_address(handle=h)
                if info:
                    return {
                        'name': info.get('name', self.process_name),
                        'path': '',
                        'base': info['base'],
                        'size': info['size'],
                    }
                modules = self.enum_modules_manual(user_only=False, handle=h)
                if modules:
                    return modules[0]
        except OSError:
            return None
        return None

    @staticmethod
    def _parse_pe_header(hdr):
        """解析 PE 头缓冲，返回 (e_lfanew, 节数, 可选头长度, 可选头 Magic)

        非法则抛 ValueError。short 读节表、long 算指针大小都走这一份。
        """
        if len(hdr) < 0x40 or hdr[:2] != b'MZ':
            raise ValueError("无效的 DOS Header")

        e_lfanew = struct.unpack_from('<I', hdr, 0x3C)[0]
        if e_lfanew + 26 > len(hdr) or hdr[e_lfanew:e_lfanew + 4] != b'PE\0\0':
            raise ValueError("无效的 PE Header")

        nsec = struct.unpack_from('<H', hdr, e_lfanew + 6)[0]
        opt_size = struct.unpack_from('<H', hdr, e_lfanew + 20)[0]
        opt_magic = struct.unpack_from('<H', hdr, e_lfanew + 24)[0]
        return e_lfanew, nsec, opt_size, opt_magic

    def get_sections_short(self, base=None):
        """短连接读 PE 头，返回节表 [{name, rva, vsize, chars}]"""
        if base is None:
            info = self.get_base_short()
            if not info:
                return []
            base = info['base']

        hdr = self.read_short(base, 0x1000)
        if not hdr:
            return []
        try:
            e_lfanew, nsec, opt_size, _ = self._parse_pe_header(hdr)
        except ValueError:
            return []

        sec_off = e_lfanew + 24 + opt_size

        sections = []
        for i in range(nsec):
            o = sec_off + i * 40
            if o + 40 > len(hdr):
                break
            name = hdr[o:o + 8].rstrip(b'\0').decode('latin1', 'ignore')
            vsize, rva = struct.unpack_from('<II', hdr, o + 8)
            chars = struct.unpack_from('<I', hdr, o + 36)[0]
            sections.append({'name': name, 'rva': rva,
                             'vsize': vsize, 'chars': chars})
        return sections

    def get_section_range_short(self, index=0, base=None, largest=False):
        """短连接取某个节的运行时范围（页对齐，绝对地址）
        largest=True 时取体积最大的节，不依赖节表顺序
        返回 {name, base, rva, start, size, end, tail}
        """
        if base is None:
            info = self.get_base_short()
            if not info:
                return None
            base = info['base']

        sections = self.get_sections_short(base)
        if not sections:
            return None
        if largest:
            index = max(range(len(sections)), key=lambda i: sections[i]['vsize'])
        if index >= len(sections):
            return None

        sec = sections[index]
        size = (sec['vsize'] + 0xFFF) & ~0xFFF
        if size == 0:
            return None

        start = base + sec['rva']
        return {
            'name': sec['name'],
            'base': base,
            'rva': sec['rva'],
            'start': start,
            'size': size,
            'end': start + size,
            'tail': start + size - 0x1000,
        }

    def search_short(self, pattern_hex, base=None, size=None,
                     chunk=4 * 1024 * 1024, find_all=True):
        """短连接特征码扫描

        算法完全复用 _pattern_plan / _iter_matches（与 _scan_single_module 同一份实现），
        区别只是数据分块用 read_short 取，所以速度和库内扫描一致。
        """
        pattern_list = self.pattern_to_bytes(pattern_hex)
        plen = len(pattern_list)
        if plen == 0:
            return []

        plan = self._pattern_plan(pattern_list)
        if plan is None:
            self.logger.error("特征码不能全是通配符")
            return []

        if base is None or size is None:
            info = self.get_base_short()
            if not info:
                return []
            base = info['base'] if base is None else base
            size = info['size'] if size is None else size

        results, seen = [], set()
        step = max(1, chunk - plen + 1)
        off = 0
        while off < size:
            data = self.read_short(base + off, min(chunk, size - off))
            if data:
                for start in self._iter_matches(data, pattern_list, plan):
                    addr = base + off + start
                    if addr not in seen:
                        seen.add(addr)
                        results.append(addr)
                        if not find_all:
                            break
            if results and not find_all:
                break
            off += step

        results.sort()
        self.logger.info(f"短连接扫描完成: {pattern_hex} -> {len(results)} 处")
        return results

    def replace_short(self, address, replacement_hex):
        """短连接在指定地址替换字节，返回 {'success', 'address', 'original', 'new'}

        address 支持 int 或十六进制字符串；replacement_hex 支持 hex 串 / bytes / bytearray。
        每次调用瞬开瞬关句柄，写入校验复用 _write_verified（和 long 版同一份逻辑）。
        """
        address = int(address, 16) if isinstance(address, str) else address
        _, replacement, replacement_display = self._parse_hex_input(replacement_hex)
        result = {'success': False, 'address': address, 'original': '', 'new': ''}

        self._log_replace_header(address, replacement_display, len(replacement))
        if not replacement:
            self.logger.error("✗ 替换字节为空")
            return result

        access = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        try:
            with self._short_handle(access) as h:
                result = self._write_verified(h, address, replacement)
        except Exception as e:
            self.logger.error(f"✗ 替换异常: {e}")
            return result

        if result['success']:
            self.logger.info("✓ 替换成功并验证通过!")
        return result

    def search_and_replace_short(self, pattern_hex, replacement_hex,
                                 base=None, size=None, replace_all=False):
        """短连接搜索并替换，返回 {'success_count', 'data', 'errors'}

        用法与 search_and_replace 一致：base/size 指定扫描范围，replace_all=False 只替换首个匹配。
        写入统一走 replace_short，每次写都会回读校验。
        """
        pattern_list = self.pattern_to_bytes(pattern_hex)
        replacement_list, replacement, _ = self._parse_hex_input(replacement_hex)

        if len(pattern_list) != len(replacement_list):
            self.logger.error(f"错误: 特征码长度({len(pattern_list)})"
                              f"与替换码长度({len(replacement_list)})不匹配")
            return {'success_count': 0, 'data': [],
                    'errors': ['特征码与替换码长度不匹配']}

        targets = self.search_short(pattern_hex, base=base, size=size,
                                    find_all=replace_all)
        if not targets:
            self.logger.error("❌ 未找到任何匹配项！")
            return {'success_count': 0, 'data': [], 'errors': ['未找到匹配项']}

        return self._replace_targets(
            [(addr, {}) for addr in targets],
            replacement,
            lambda addr, data: self.replace_short(addr, data),
        )

    @staticmethod
    def is_system_module(module_name, module_path=""):
        """判断是否为系统模块"""
        module_lower = module_name.lower()
        
        system_prefixes = [
            'ntdll.', 'kernel32.', 'kernelbase.',
            'user32.', 'gdi32.', 'advapi32.',
            'msvcr', 'msvcp', 'vcruntime',
            'ucrtbase.', 'combase.', 'rpcrt4.',
            'ole32.', 'oleaut32.', 'shell32.',
            'shlwapi.', 'ws2_32.', 'bcrypt.',
            'crypt32.', 'sechost.', 'win32u.'
        ]
        
        system_dirs = ['\\windows\\', '\\system32\\', '\\syswow64\\']
        
        for prefix in system_prefixes:
            if module_lower.startswith(prefix):
                return True
        
        if module_path:
            path_lower = module_path.lower()
            for sys_dir in system_dirs:
                if sys_dir in path_lower:
                    return True
        
        return False
    
    @staticmethod
    def pattern_to_bytes(pattern_hex):
        """将特征码字符串转换为字节列表"""
        hex_parts = pattern_hex.replace(' ', '').upper()
        byte_list = []
        for i in range(0, len(hex_parts), 2):
            byte_str = hex_parts[i:i+2]
            if byte_str == '??':
                byte_list.append(None)
            else:
                byte_list.append(int(byte_str, 16))
        return byte_list

    @staticmethod
    def extract_bytes(hex_string, length_or_start, end=None):
        """从十六进制字符串中提取字节"""
        if not hex_string:
            return ""
        
        hex_list = hex_string.split()
        
        if end is None:
            n = length_or_start
            if n <= 0 or n > len(hex_list):
                n = len(hex_list)
            result = " ".join(hex_list[:n])
        else:
            start = length_or_start
            if start < 0 or start >= len(hex_list):
                return ""
            if end < 0 or end > len(hex_list):
                end = len(hex_list)
            result = " ".join(hex_list[start:end])
        
        return result

    @staticmethod
    def bytes_list_to_bytes(byte_list):
        """将字节列表转换为实际的 bytes 对象"""
        return bytes(b if b is not None else 0 for b in byte_list)

    def _parse_hex_input(self, value):
        """把 hex 字符串 / bytes / bytearray 统一成 (字节列表, bytes, 展示用 hex)

        long / short 两套替换接口共用这一份解析，不再各写一遍 isinstance 分支。
        """
        if isinstance(value, (bytes, bytearray)):
            data = bytes(value)
            return list(data), data, data.hex(' ').upper()
        if isinstance(value, str):
            byte_list = self.pattern_to_bytes(value)
            return byte_list, self.bytes_list_to_bytes(byte_list), value
        raise TypeError(f"不支持的替换参数类型: {type(value).__name__}，"
                        f"请使用十六进制字符串、bytes 或 bytearray")
    
    def enum_modules_manual(self, user_only=True, handle=None):
        """手动枚举进程模块（可传短连接句柄，不依赖 self.pm）"""
        handle = handle or self.pm.process_handle
        try:
            hModules = (wintypes.HMODULE * MODULE_BUFFER_SIZE)()
            cbNeeded = wintypes.DWORD()
            
            if not psapi.EnumProcessModules(
                handle,
                hModules,
                ctypes.sizeof(hModules),
                ctypes.byref(cbNeeded)
            ):
                err_code = ctypes.get_last_error()
                self.logger.error(f"EnumProcessModules 失败 | 错误码: {err_code}")
                return []
            
            module_count = cbNeeded.value // ctypes.sizeof(wintypes.HMODULE)
            
            modules = []
            system_modules_skipped = 0
            
            for i in range(module_count):
                modinfo = MODULEINFO()
                hModule = hModules[i]
                
                if psapi.GetModuleInformation(
                    handle,
                    hModule,
                    ctypes.byref(modinfo),
                    ctypes.sizeof(modinfo)
                ):
                    module_name = ctypes.create_unicode_buffer(MAX_MODULE_NAME_LENGTH)
                    psapi.GetModuleBaseNameW(
                        handle,
                        hModule,
                        module_name,
                        MAX_MODULE_NAME_LENGTH
                    )
                    
                    module_path = ctypes.create_unicode_buffer(MAX_MODULE_NAME_LENGTH)
                    psapi.GetModuleFileNameExW(
                        handle,
                        hModule,
                        module_path,
                        MAX_MODULE_NAME_LENGTH
                    )
                    
                    if user_only and self.is_system_module(module_name.value, module_path.value):
                        system_modules_skipped += 1
                        continue
                    
                    modules.append({
                        'name': module_name.value,
                        'path': module_path.value,
                        'base': modinfo.lpBaseOfDll,
                        'size': modinfo.SizeOfImage
                    })
            
            if user_only:
                self.logger.info(f"\n找到 {module_count} 个模块 (已跳过 {system_modules_skipped} 个系统模块)")
                self.logger.info(f"用户模块数量: {len(modules)}")
            else:
                self.logger.info(f"\n找到 {module_count} 个模块")
            
            return modules
        
        except Exception as e:
            self.logger.error(f"枚举进程模块时发生异常: {str(e)}")
            return []

    
    @staticmethod
    def _pattern_plan(pattern_list):
        """把特征码编译成扫描计划：(锚点, 锚点起始位, 锚点外待校验位)

        取最长连续固定串做锚点，候选量 = 锚点命中数；锚点覆盖的固定位无需再校验。
        全是通配符时返回 None。
        """
        fixed_positions = [i for i, b in enumerate(pattern_list) if b is not None]
        if not fixed_positions:
            return None

        best_start = best_length = 0
        current_start = current_length = 0

        for i, b in enumerate(pattern_list):
            if b is not None:
                if current_length == 0:
                    current_start = i
                current_length += 1
                if current_length > best_length:
                    best_start = current_start
                    best_length = current_length
            else:
                current_length = 0

        anchor = bytes(pattern_list[best_start:best_start + best_length])
        verify_positions = [
            pos for pos in fixed_positions
            if not best_start <= pos < best_start + best_length
        ]
        return anchor, best_start, verify_positions

    @classmethod
    def _iter_matches(cls, data, pattern_list, plan):
        """按锚点在 data 里逐个产出匹配起点：C 层 find 找候选 + 少量逐字节校验"""
        anchor, best_start, verify_positions = plan
        pattern_length = len(pattern_list)
        max_offset = len(data) - pattern_length

        pos = data.find(anchor)
        while pos >= 0:
            start = pos - best_start
            if 0 <= start <= max_offset:
                for p in verify_positions:
                    if data[start + p] != pattern_list[p]:
                        break
                else:
                    yield start
            pos = data.find(anchor, pos + 1)

    def _scan_single_module(self, module, pattern_list, find_all=True):
        """高性能扫描单个模块（算法见 _pattern_plan / _iter_matches）"""
        matches = []

        try:
            module_bytes = self.pm.read_bytes(
                module['base'],
                module['size']
            )

            pattern_length = len(pattern_list)
            module_length = len(module_bytes)

            if pattern_length == 0:
                return module_bytes, matches

            if module_length < pattern_length:
                return module_bytes, matches

            plan = self._pattern_plan(pattern_list)

            if plan is None:
                # 全通配：没有锚点可找，按原语义返回首个 / 全部位置
                offsets = (range(1) if not find_all
                           else range(module_length - pattern_length + 1))
                for offset in offsets:
                    matches.append({
                        'offset': offset,
                        'bytes': module_bytes[offset:offset + pattern_length]
                    })
                return module_bytes, matches

            for offset in self._iter_matches(module_bytes, pattern_list, plan):
                matches.append({
                    'offset': offset,
                    'bytes': module_bytes[offset:offset + pattern_length]
                })
                if not find_all:
                    break

            return module_bytes, matches

        except Exception as e:
            self.logger.error(
                f"  ✗ 读取/扫描失败: {e}"
            )

            return None, []
    
    def _pattern_scan_generator(self, modules, pattern_list):
        """生成器版本，只扫描到第一个匹配结果"""
        for mod in modules:
            module_bytes, matches = self._scan_single_module(
                mod,
                pattern_list,
                find_all=False
            )

            if module_bytes is None:
                continue

            if matches:
                match = matches[0]

                yield {
                    'module': mod,
                    'offset': match['offset'],
                    'matched_bytes': match['bytes'],
                    'address': mod['base'] + match['offset']
                }

                return
    
    def _pattern_scan_core(self, pattern_list, find_all=True, user_only=True, return_detailed=False, base_only=False):
        """
        核心扫描方法
        Args:
            pattern_list: 模式字节列表
            find_all: 是否查找所有匹配
            user_only: 是否只扫描用户模块
            return_detailed: 是否返回详细结果
            base_only: 是否只扫描基础模块
        Returns:
            如果 return_detailed=True: 返回详细字典列表
            否则: 返回地址列表
        """
        modules = []
        if base_only:
            if self.base_module_info:
                modules = [self.base_module_info]
            else:
                self.logger.error("错误: 未获取到基础模块信息!")
                return [] if return_detailed else []
        else:
            modules = self.enum_modules_manual(user_only=user_only)
        
        if not modules:
            self.logger.error("错误: 无法枚举模块!")
            return [] if return_detailed else []
        
        self.logger.info(f"\n开始扫描 {len(modules)} 个模块...")
        if base_only:
            self.logger.info(f"范围: 基础模块 ({modules[0]['name']})")
        else:
            self.logger.info(f"范围: {'用户模块' if user_only else '所有模块'}")
        self.logger.info("\n将要扫描的模块:")
        for mod in modules:
            self.logger.info(f"  - {mod['name']} (0x{mod['base']:X})")
            if mod.get('path'):
                self.logger.info(f"    路径: {mod['path']}")

        if not find_all and not return_detailed:
            generator = self._pattern_scan_generator(modules, pattern_list)
            for match in generator:
                return [match['address']]
            return []
        
        results = []
        addresses = []
        total_matches = 0
        
        for mod in modules:
            mod_name = mod['name']
            mod_base = mod['base']
            mod_size = mod['size']
            
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"模块: {mod_name}")
            self.logger.info(f"基址: 0x{mod_base:X}")
            self.logger.info(f"大小: 0x{mod_size:X} ({mod_size:,} bytes)")
            
            module_bytes, matches = self._scan_single_module(mod, pattern_list)
            
            if module_bytes is None:
                continue
            
            matches_in_module = 0
            for match in matches:
                offset = match['offset']
                matched_bytes = match['bytes']
                addr = mod_base + offset
                matches_in_module += 1
                total_matches += 1
                
                if return_detailed:
                    result = {
                        'address': addr,
                        'bytes': matched_bytes,
                        'hex': matched_bytes.hex(' ').upper(),
                        'module': mod_name,
                        'module_base': mod_base,
                        'offset': offset
                    }
                    results.append(result)
                else:
                    addresses.append(addr)
                
                if return_detailed:
                    self.logger.info(f"  ✓ 找到匹配 #{matches_in_module}:")
                    self.logger.info(f"    地址: 0x{addr:X}")
                    self.logger.info(f"    字节: {result['hex']}")
                    self.logger.info(f"    偏移: +0x{offset:X}")
                else:
                    self.logger.info(f"  ✓ 找到匹配 #{matches_in_module}: 0x{addr:X}")
                    self.logger.info(f"    字节: {matched_bytes.hex(' ').upper()}")
                
                if not find_all:
                    break

            if matches_in_module == 0:
                self.logger.info(f"  未找到匹配")
            else:
                self.logger.info(f"  本模块共找到 {matches_in_module} 个匹配")
            
            if not find_all and (addresses or results):
                break
        
        if return_detailed:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"搜索完成! 总共找到 {len(results)} 个匹配项")
            self.logger.info(f"{'='*60}")
        else:
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"搜索完成! 总共找到 {len(addresses)} 个匹配项")
            self.logger.info(f"{'='*60}")
        
        return results if return_detailed else addresses

    def _write_bytes_with_protection(self, address, replacement_bytes, original_bytes=None):
        """（长期连接版）写入并校验，逻辑复用 _write_verified，只是句柄来自 self.pm"""
        if not self.pm:
            self.logger.error("✗ 未连接到进程")
            return {'success': False, 'address': address, 'original': '', 'new': ''}

        data = bytes(replacement_bytes)
        if original_bytes is not None and len(original_bytes) != len(data):
            original_bytes = None      # 长度不符就重读，避免校验错位

        return self._write_verified(self.pm.process_handle, address, data, original_bytes)
    
    def _wait_and_cleanup_remote_thread(self, thread_handle, shellcode_addr):
        """等待注入的代码执行完毕并清理"""
        kernel32.WaitForSingleObject(thread_handle, 5000000)
        kernel32.CloseHandle(thread_handle)
        self.logger.info("shellcode执行完毕")
        time.sleep(1)
        self.pm.free(shellcode_addr)
    
    def search(self, pattern_hex, find_all=True, user_only=True, base_only=False):
        """搜索特征码（使用十六进制字符串）"""
        pattern_list = self.pattern_to_bytes(pattern_hex)
        
        self._log_scan_header(pattern_hex, len(pattern_list), user_only, base_only)

        return self._pattern_scan_core(
            pattern_list=pattern_list,
            find_all=find_all,
            user_only=user_only,
            return_detailed=True,
            base_only=base_only
        )
        
    def replace(self, address, replacement_hex):
        """在指定地址替换字节（长期连接版）

        参数解析、日志头、写入校验全部复用 short 版同一份实现，
        区别只是句柄来自 self.pm。
        """
        try:
            address = int(address, 16) if isinstance(address, str) else address

            _, replacement_bytes, replacement_display = \
                self._parse_hex_input(replacement_hex)

            self._log_replace_header(address, replacement_display,
                                     len(replacement_bytes),
                                     type(replacement_hex).__name__)

            result = self._write_bytes_with_protection(address, replacement_bytes)

            if result['success']:
                self.logger.info("✓ 替换成功并验证通过!")
            else:
                self.logger.error("✗ 替换失败")

            return {'address': address, 'original': result['original'], 'new': result['new']}

        except Exception as e:
            self.logger.error(f"✗ 替换异常: {e}")
            return {'address': address, 'original': '', 'new': ''}

    def search_and_replace(self, pattern_hex, replacement_hex, replace_all=False,
                           user_only=True, base_only=False):
        """搜索特征码并替换（长期连接版）

        参数解析、日志头、替换循环全部复用 short 版的同一份实现，
        差别只在于扫描走 _pattern_scan_core、写入走 self.pm 的句柄。
        """
        pattern_list = self.pattern_to_bytes(pattern_hex)
        replacement_list, replacement_bytes, replacement_display = \
            self._parse_hex_input(replacement_hex)

        if len(replacement_list) != len(pattern_list):
            self.logger.error(f"错误: 特征码长度({len(pattern_list)})"
                              f"与替换码长度({len(replacement_list)})不匹配")
            return {"success_count": 0, "data": [], "errors": ["长度不匹配"]}

        self._log_scan_header(pattern_hex, len(pattern_list), user_only,
                              base_only, replacement_display)

        results = self._pattern_scan_core(
            pattern_list=pattern_list,
            find_all=replace_all,
            user_only=user_only,
            return_detailed=True,
            base_only=base_only
        )

        if not results:
            self.logger.error("\n❌ 未找到任何匹配项！")
            return {"success_count": 0, "data": [], "errors": ["未找到匹配项"]}

        return self._replace_targets(
            [(m['address'], {'module': m['module'],
                             'module_base': m['module_base'],
                             'offset': m['offset']}) for m in results],
            replacement_bytes,
            lambda addr, data: self._write_bytes_with_protection(addr, data),
        )

    def inject_shellcode(self, shellcode):
        """代码注入"""
        shellcode_length = len(shellcode)
        shellcode_addr = self.pm.allocate(shellcode_length)
        self.change_memory_protection(shellcode_addr, shellcode_length)
        self.write_value(shellcode_addr, shellcode, "bytes")
        self.logger.info(f"写入sheellcode成功，地址：0x{shellcode_addr:X}，长度：{shellcode_length}")
        thread_h = kernel32.CreateRemoteThread(
            self.pm.process_handle,
            None,
            0,
            ctypes.c_void_p(shellcode_addr),
            None,
            0,
            None
        )
        if thread_h:
            cleanup_thread = threading.Thread(
                target=self._wait_and_cleanup_remote_thread,
                args=(thread_h, shellcode_addr),
                daemon=True
            )
            cleanup_thread.start()
        else:
            error_code = kernel32.GetLastError()
            self.logger.error(f"✗ 创建远程线程失败，错误代码: {error_code}")
        
    def _virtual_protect(self, address, size, protect):
        """改 self.pm 目标的页保护，成功返回原保护 DWORD，失败返回 None"""
        old_protect = wintypes.DWORD()
        if not kernel32.VirtualProtectEx(
            self.pm.process_handle,
            ctypes.c_void_p(address),
            ctypes.c_size_t(size),
            protect,
            ctypes.byref(old_protect)
        ):
            return None
        return old_protect

    def change_memory_protection(self, address, size):
        """修改内存页保护属性（标为可读写执行）"""
        old_protect = self._virtual_protect(address, size, PAGE_EXECUTE_READWRITE)
        if old_protect is None:
            return
        self.logger.info(f"内存权限修改成功，原权限: 0x{old_protect.value:X}")
        return old_protect

    def restore_memory_protection(self, address, size, protect):
        """恢复内存保护属性"""
        if self._virtual_protect(address, size, protect) is None:
            self.logger.error(f"  恢复保护失败，错误码: {ctypes.get_last_error()}")

    def get_module_base_address(self, handle=None):
        """获取模块基地址（可传短连接句柄，不依赖 self.pm）"""
        handle = handle or (self.pm.process_handle if self.pm else None)
        if handle:
            try:
                module = pymem.process.module_from_name(handle, self.process_name)
                return {
                    'base': module.lpBaseOfDll,
                    'size': module.SizeOfImage,
                    'name': self.process_name
                }
            except Exception as e:
                self.logger.error(f"获取模块基地址失败: {e}")
                return None

    def _get_pointer_size(self):
        """根据目标进程主模块 PE 头判断指针大小（4/8字节），解析复用 _parse_pe_header"""
        if not self.pm or self.base_module_info is None:
            raise RuntimeError("未连接到进程或未获取基址")

        base = self.base_module_info['base']

        try:
            _, _, _, optional_magic = self._parse_pe_header(
                self.pm.read_bytes(base, 0x1000)
            )

            if optional_magic == 0x20B:
                return 8
            if optional_magic == 0x10B:
                return 4

            raise RuntimeError(f"未知 Optional Header Magic: 0x{optional_magic:X}")

        except Exception as e:
            raise RuntimeError(f"无法判断目标进程指针大小: {e}")

    def calculate_pointer_chain(self, base_offset, offsets):
        """计算指针链地址"""
        if not self.pm or self.base_module_info is None:
            raise RuntimeError("未连接到进程或未获取基址")

        if not offsets:
            return self.base_module_info['base'] + base_offset

        pointer_size = self._get_pointer_size()

        current_address = self.base_module_info['base'] + base_offset

        for i, offset in enumerate(offsets):
            try:
                pointer_bytes = self.pm.read_bytes(
                    current_address,
                    pointer_size
                )

                pointer_value = int.from_bytes(
                    pointer_bytes,
                    byteorder='little',
                    signed=False
                )

                current_address = pointer_value + offset

            except pymem.exception.MemoryReadError:
                raise ValueError(
                    f"指针链第 {i + 1} 层解引用失败 "
                    f"(地址: 0x{current_address:X})"
                )

            except Exception as e:
                raise ValueError(
                    f"指针链第 {i + 1} 层计算失败 "
                    f"(地址: 0x{current_address:X}): {e}"
                )

        return current_address
    
    def write_value(self, address, value, data_type='int'):
        """写入内存值"""
        if not self.pm:
            return False
        
        try:
            if data_type == 'int':
                self.pm.write_int(address, int(value))
            elif data_type == 'float':
                self.pm.write_float(address, float(value))
            elif data_type == 'double':
                self.pm.write_double(address, float(value))
            elif data_type == 'bool':
                self.pm.write_bool(address, bool(value))
            elif data_type == 'bytes':
                self.pm.write_bytes(address, bytes(value), len(bytes(value)))
            else:
                self.logger.error(f"不支持的数据类型: {data_type}")
                return False
            return True
        except Exception as e:
            self.logger.error(f"写入内存失败: {e}")
            return False
    
    def read_value(self, address, data_type='int'):
        """读取内存值"""
        if not self.pm:
            return None
        
        try:
            if data_type == 'int':
                return self.pm.read_int(address)
            elif data_type == 'float':
                return self.pm.read_float(address)
            elif data_type == 'double':
                return self.pm.read_double(address)
            elif data_type == 'bool':
                return self.pm.read_bool(address)
            elif data_type == 'bytes':
                return self.pm.read_bytes(address, 4)
            elif data_type == 'byte':
                return self.pm.read_bytes(address, 1)
            else:
                self.logger.error(f"不支持的数据类型: {data_type}")
                return None
        except Exception as e:
            self.logger.error(f"读取内存失败: {e}")
            return None

    def lock_value(self, address, value, data_type='int', interval=0.05, lock_id=None):
        """
        锁定内存值
        """
        if not self.pm:
            self.logger.error("未连接到进程")
            return None
            
        address = int(address, 16) if isinstance(address, str) else address
        
        with self._lock_threads_lock:
            if lock_id is None:
                self._lock_counter += 1
                lock_id = f"lock_{self._lock_counter}"
            
            if lock_id in self._lock_threads:
                self.logger.warning(f"锁定ID '{lock_id}' 已存在，将先解锁旧任务")
                self._unlock_value_internal(lock_id)
        
        stop_event = threading.Event()
        
        def lock_thread():
            self.logger.info(f"[{lock_id}] 开始锁定 0x{address:X} = {value} ({data_type})")
            write_count = 0
            error_count = 0
            
            while not stop_event.is_set():
                try:
                    success = self.write_value(address, value, data_type)
                    if success:
                        write_count += 1
                    else:
                        error_count += 1
                        if error_count > 10:
                            self.logger.error(f"[{lock_id}] 连续写入失败，停止锁定")
                            break
                except Exception as e:
                    error_count += 1
                    if error_count <= 3:
                        self.logger.error(f"[{lock_id}] 写入异常: {e}")
                    if error_count > 10:
                        break
                
                time.sleep(interval)
            
            self.logger.info(f"[{lock_id}] 停止锁定 (总写入: {write_count}, 错误: {error_count})")
        
        thread = threading.Thread(target=lock_thread, daemon=True, name=f"MemLock-{lock_id}")
        thread.start()
        
        with self._lock_threads_lock:
            self._lock_threads[lock_id] = {
                'thread': thread,
                'stop_event': stop_event,
                'info': {
                    'address': address,
                    'value': value,
                    'data_type': data_type,
                    'interval': interval,
                    'start_time': time.time()
                }
            }
        
        return lock_id
    
    def unlock_value(self, lock_id):
        """
        解锁指定的内存值
        """
        with self._lock_threads_lock:
            return self._unlock_value_internal(lock_id)
    
    def _unlock_value_internal(self, lock_id):
        """内部解锁方法"""
        if lock_id not in self._lock_threads:
            self.logger.warning(f"锁定ID '{lock_id}' 不存在")
            return False
        
        lock_info = self._lock_threads[lock_id]
        lock_info['stop_event'].set()
        lock_info['thread'].join(timeout=1.0)
        
        del self._lock_threads[lock_id]
        self.logger.info(f"已解锁 '{lock_id}'")
        return True
    
    def unlock_all(self):
        """解锁所有内存值"""
        with self._lock_threads_lock:
            lock_ids = list(self._lock_threads.keys())
        
        count = 0
        for lock_id in lock_ids:
            if self.unlock_value(lock_id):
                count += 1
        
        self.logger.info(f"已解锁所有任务 (共 {count} 个)")
        return count
    
    def get_active_locks(self):
        """ 获取所有活跃的锁定任务信息 """
        with self._lock_threads_lock:
            return {
                lock_id: data['info'].copy() 
                for lock_id, data in self._lock_threads.items()
            }

    def get_hwnds(self):
        """获取目标进程的所有窗口句柄及详细信息"""
        windows_info = []
        target_pid = self.pm.process_id
        
        def callback(hwnd, extra):
            if user32.IsWindowVisible(hwnd):
                window_pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
                
                if window_pid.value == target_pid:
                    length = user32.GetWindowTextLengthW(hwnd) + 1
                    title_buffer = ctypes.create_unicode_buffer(length)
                    user32.GetWindowTextW(hwnd, title_buffer, length)
                    window_title = title_buffer.value
                    
                    class_buffer = ctypes.create_unicode_buffer(256)
                    user32.GetClassNameW(hwnd, class_buffer, 256)
                    window_class = class_buffer.value
                    
                    rect = wintypes.RECT()
                    user32.GetWindowRect(hwnd, ctypes.byref(rect))
                    
                    is_iconic = user32.IsIconic(hwnd)
                    is_zoomed = user32.IsZoomed(hwnd)
                    
                    is_enabled = user32.IsWindowEnabled(hwnd)
                    
                    parent_hwnd = user32.GetParent(hwnd)
                    
                    window_info = {
                        'hwnd': hwnd,
                        'pid': window_pid.value,
                        'title': window_title,
                        'class_name': window_class,
                        'rect': {
                            'left': rect.left,
                            'top': rect.top,
                            'right': rect.right,
                            'bottom': rect.bottom,
                            'width': rect.right - rect.left,
                            'height': rect.bottom - rect.top
                        },
                        'position': (rect.left, rect.top),
                        'size': (rect.right - rect.left, rect.bottom - rect.top),
                        'is_visible': True,
                        'is_enabled': bool(is_enabled),
                        'is_minimized': bool(is_iconic),
                        'is_maximized': bool(is_zoomed),
                        'parent_hwnd': parent_hwnd,
                    }
                    
                    windows_info.append(window_info)
            return True
        
        enum_func = EnumWindowsProc(callback)
        user32.EnumWindows(enum_func, 0)
        
        return windows_info
        
    def get_function_address(self, dll_name, function_name):
        """获取函数地址"""
        if self.is_system_module(dll_name):
            return self._get_system_api_address(dll_name, function_name)
        else:
            return self._get_private_dll_address(dll_name, function_name)
    
    def _get_system_api_address(self, dll_name, function_name):
        """快速获取系统API地址"""
        try:
            dll_obj = ctypes.WinDLL(dll_name)
            func_obj = getattr(dll_obj, function_name)
            func_address = ctypes.cast(func_obj, ctypes.c_void_p).value
            
            self.logger.info(f"[+] 系统API: {dll_name}!{function_name}")
            self.logger.info(f"    地址: 0x{func_address:X}")
            
            return func_address
            
        except AttributeError:
            self.logger.info(f"[-] 函数不存在: {dll_name}!{function_name}")
            return None
        except OSError as e:
            self.logger.info(f"[-] DLL加载失败: {dll_name}")
            self.logger.info(f"    提示: 请确认DLL名称正确或改用 is_system_dll=False")
            return None
        except Exception as e:
            self.logger.info(f"[-] 获取失败: {e}")
            return None
    
    def _get_private_dll_address(self, dll_name, function_name):
        """解析目标进程的私有DLL"""
        try:
            
            dll_base = pymem.process.module_from_name(self.pm.process_handle, dll_name).lpBaseOfDll
            self.logger.info(f"[+] 私有DLL: {dll_name}")
            self.logger.info(f"    基址: 0x{dll_base:X}")
            
            # === 读取DOS头 ===
            dos_header = self.pm.read_bytes(dll_base, 64)
            e_magic = struct.unpack('<H', dos_header[0:2])[0]
            
            if e_magic != 0x5A4D:  # "MZ"
                self.logger.info("[-] 无效的DOS签名")
                return None
            
            e_lfanew = struct.unpack('<I', dos_header[60:64])[0]
            
            # === 读取PE头 ===
            pe_header_addr = dll_base + e_lfanew
            pe_header = self.pm.read_bytes(pe_header_addr, 264)
            
            pe_signature = struct.unpack('<I', pe_header[0:4])[0]
            if pe_signature != 0x00004550:  # "PE\0\0"
                self.logger.info("[-] 无效的PE签名")
                return None
            
            # 判断架构
            machine = struct.unpack('<H', pe_header[4:6])[0]
            is_64bit = (machine == 0x8664)
            arch = "x64" if is_64bit else "x86"
            self.logger.info(f"    架构: {arch}")
            
            # === 获取导出表 ===
            export_dir_rva_offset = 136 if is_64bit else 120
            export_dir_rva = struct.unpack('<I', pe_header[export_dir_rva_offset:export_dir_rva_offset+4])[0]
            
            if export_dir_rva == 0:
                self.logger.info("[-] 该DLL没有导出表")
                return None
            
            # === 读取导出目录 ===
            export_dir_addr = dll_base + export_dir_rva
            export_dir = self.pm.read_bytes(export_dir_addr, 40)
            
            num_of_names = struct.unpack('<I', export_dir[24:28])[0]
            addr_of_funcs_rva = struct.unpack('<I', export_dir[28:32])[0]
            addr_of_names_rva = struct.unpack('<I', export_dir[32:36])[0]
            addr_of_ords_rva = struct.unpack('<I', export_dir[36:40])[0]
            
            self.logger.info(f"    导出函数: {num_of_names} 个")
            
            # === 遍历导出名称表 ===
            for i in range(num_of_names):
                # 读取名称RVA
                name_rva_addr = dll_base + addr_of_names_rva + (i * 4)
                name_rva = struct.unpack('<I', self.pm.read_bytes(name_rva_addr, 4))[0]
                
                name_addr = dll_base + name_rva
                current_name = self.pm.read_string(name_addr, 256)
                
                if current_name == function_name:
                    ordinal_addr = dll_base + addr_of_ords_rva + (i * 2)
                    ordinal = struct.unpack('<H', self.pm.read_bytes(ordinal_addr, 2))[0]
                    
                    func_addr_rva_addr = dll_base + addr_of_funcs_rva + (ordinal * 4)
                    func_rva = struct.unpack('<I', self.pm.read_bytes(func_addr_rva_addr, 4))[0]
                    func_addr = dll_base + func_rva
                    
                    self.logger.info(f"[+] 找到函数: {function_name}")
                    self.logger.info(f"    RVA: 0x{func_rva:X}")
                    self.logger.info(f"    绝对地址: 0x{func_addr:X}")
                    
                    return func_addr
            
            self.logger.info(f"[-] 函数未找到: {function_name}")
            return None
            
        except Exception as e:
            self.logger.info(f"[-] 解析私有DLL失败: {e}")
            return None
            
    def alloc_near(self, target_addrs, size):
        """在目标地址附近分配内存"""
        if isinstance(target_addrs, int):
            target_addrs = [target_addrs]
        
        self.logger.info(f"目标地址: {[f'{addr:016X}' for addr in target_addrs]}")
        
        min_addr = min(target_addrs)
        max_addr = max(target_addrs)
        
        search_start = max(0x10000, min_addr - 0x7FFF0000)
        search_end = max_addr + 0x7FFF0000
        search_addr = search_start
        attempts = 0
        
        while search_addr < search_end:
            attempts += 1
            addr = kernel32.VirtualAllocEx(
                self.pm.process_handle,
                ctypes.c_uint64(search_addr),
                size,
                0x3000,
                0x40
            )
            
            if addr and addr != 0:
                all_in_range = True
                for target_addr in target_addrs:
                    rel32 = addr - (target_addr + 6)
                    if not (-0x80000000 <= rel32 <= 0x7FFFFFFF):
                        all_in_range = False
                        break
                
                if all_in_range:
                    self.logger.info(f"✓ 成功！尝试 #{attempts}, 分配在 {addr:016X}")
                    return addr
                else:
                    kernel32.VirtualFreeEx(self.pm.process_handle, ctypes.c_uint64(addr), 0, 0x8000)
            
            search_addr += 0x10000
            if attempts % 100 == 0:
                self.logger.info(f"已尝试 {attempts} 次, 当前地址: {search_addr:016X}")
        
        raise Exception(f"找不到合适的地址！共尝试 {attempts} 次")
    
    def inject_dll(self, dll_path):
        """注入DLL"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        if not os.path.isabs(dll_path):
            dll_path = os.path.join(current_dir, dll_path)
        
        if not os.path.exists(dll_path):
            self.logger.error(f"DLL文件不存在: {dll_path}")
            return False
        
        try:
            pymem.process.inject_dll_from_path(self.pm.process_handle, dll_path)
            self.logger.info(f"注入DLL成功: {dll_path}")
            return True
        except Exception as e:
            self.logger.error(f"注入DLL失败: {e}")
            return False
