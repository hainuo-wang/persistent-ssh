"""Minimal Windows ConPTY host. No third-party dependencies."""
import ctypes as C
from ctypes import wintypes as W
import os
import queue
import subprocess
import threading


class COORD(C.Structure):
    _fields_ = [('X', C.c_short), ('Y', C.c_short)]


class STARTUPINFO(C.Structure):
    _fields_ = [('cb', W.DWORD), ('lpReserved', W.LPWSTR), ('lpDesktop', W.LPWSTR),
                ('lpTitle', W.LPWSTR), ('dwX', W.DWORD), ('dwY', W.DWORD),
                ('dwXSize', W.DWORD), ('dwYSize', W.DWORD), ('dwXCountChars', W.DWORD),
                ('dwYCountChars', W.DWORD), ('dwFillAttribute', W.DWORD),
                ('dwFlags', W.DWORD), ('wShowWindow', W.WORD), ('cbReserved2', W.WORD),
                ('lpReserved2', C.POINTER(C.c_byte)), ('hStdInput', W.HANDLE),
                ('hStdOutput', W.HANDLE), ('hStdError', W.HANDLE)]


class STARTUPINFOEX(C.Structure):
    _fields_ = [('StartupInfo', STARTUPINFO), ('lpAttributeList', C.c_void_p)]


class PROCESS_INFORMATION(C.Structure):
    _fields_ = [('hProcess', W.HANDLE), ('hThread', W.HANDLE),
                ('dwProcessId', W.DWORD), ('dwThreadId', W.DWORD)]


K = C.WinDLL('kernel32', use_last_error=True)


def api(name, restype, *args):
    fn = getattr(K, name)
    fn.restype = restype
    fn.argtypes = list(args)
    return fn


CreatePipe = api('CreatePipe', W.BOOL, C.POINTER(W.HANDLE), C.POINTER(W.HANDLE), C.c_void_p, W.DWORD)
CreatePseudoConsole = api('CreatePseudoConsole', C.c_long, COORD, W.HANDLE, W.HANDLE, W.DWORD, C.POINTER(W.HANDLE))
ClosePseudoConsole = api('ClosePseudoConsole', None, W.HANDLE)
CloseHandle = api('CloseHandle', W.BOOL, W.HANDLE)
SetHandleInformation = api('SetHandleInformation', W.BOOL, W.HANDLE, W.DWORD, W.DWORD)
InitAttrs = api('InitializeProcThreadAttributeList', W.BOOL, C.c_void_p, W.DWORD, W.DWORD, C.POINTER(C.c_size_t))
UpdateAttrs = api('UpdateProcThreadAttribute', W.BOOL, C.c_void_p, W.DWORD, C.c_size_t, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p)
DeleteAttrs = api('DeleteProcThreadAttributeList', None, C.c_void_p)
CreateProcess = api('CreateProcessW', W.BOOL, W.LPCWSTR, W.LPWSTR, C.c_void_p, C.c_void_p, W.BOOL, W.DWORD, C.c_void_p, W.LPCWSTR, C.POINTER(STARTUPINFOEX), C.POINTER(PROCESS_INFORMATION))
ReadFile = api('ReadFile', W.BOOL, W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p)
WriteFile = api('WriteFile', W.BOOL, W.HANDLE, C.c_void_p, W.DWORD, C.POINTER(W.DWORD), C.c_void_p)
GetExitCode = api('GetExitCodeProcess', W.BOOL, W.HANDLE, C.POINTER(W.DWORD))
TerminateProcess = api('TerminateProcess', W.BOOL, W.HANDLE, W.UINT)
GetCurrentProcess = api('GetCurrentProcess', W.HANDLE)
IsProcessInJob = api('IsProcessInJob', W.BOOL, W.HANDLE, W.HANDLE, C.POINTER(W.BOOL))


def inside_job():
    flag = W.BOOL()
    if not IsProcessInJob(GetCurrentProcess(), None, C.byref(flag)):
        raise C.WinError(C.get_last_error())
    return bool(flag.value)


def job_limits():
    if not inside_job():
        return 0
    query = api('QueryInformationJobObject', W.BOOL, W.HANDLE, C.c_int, C.c_void_p, W.DWORD, C.c_void_p)
    buffer = C.create_string_buffer(144)
    check(query(None, 9, buffer, len(buffer), None))
    return int.from_bytes(buffer.raw[16:20], 'little')


def check(ok):
    if not ok:
        raise C.WinError(C.get_last_error())


class Terminal:
    def __init__(self, argv, callback, cwd=None):
        self.callback = callback
        self.closed = False
        self.queue = queue.Queue(maxsize=64)
        self.error = None
        ir, iw, ore, ow = W.HANDLE(), W.HANDLE(), W.HANDLE(), W.HANDLE()
        sr, sw, rr, rw = W.HANDLE(), W.HANDLE(), W.HANDLE(), W.HANDLE()
        self.pc = W.HANDLE()
        self.process = None
        self.input = None
        self.output = None
        self.console_input = None
        self.console_output = None
        attrs = None
        try:
            check(CreatePipe(C.byref(ir), C.byref(iw), None, 0))
            check(CreatePipe(C.byref(ore), C.byref(ow), None, 0))
            hr = CreatePseudoConsole(COORD(160, 30), ir, ow, 0, C.byref(self.pc))
            if hr < 0:
                raise OSError('CreatePseudoConsole HRESULT ' + hex(hr & 0xffffffff))
            size = C.c_size_t()
            # Raw standard streams carry protocol data without terminal rendering.
            # The attached pseudoconsole is used only by SSH's console password reader.
            check(CreatePipe(C.byref(sr), C.byref(sw), None, 0))
            check(CreatePipe(C.byref(rr), C.byref(rw), None, 0))
            check(SetHandleInformation(sr, 1, 1))
            check(SetHandleInformation(rw, 1, 1))
            InitAttrs(None, 2, 0, C.byref(size))
            attrs = C.create_string_buffer(size.value)
            check(InitAttrs(attrs, 2, 0, C.byref(size)))
            check(UpdateAttrs(attrs, 0, 0x00020016, self.pc, C.sizeof(W.HANDLE), None, None))
            inherited = (W.HANDLE * 2)(sr.value, rw.value)
            check(UpdateAttrs(attrs, 0, 0x00020002, C.cast(inherited, C.c_void_p), C.sizeof(inherited), None, None))
            si = STARTUPINFOEX()
            si.StartupInfo.cb = C.sizeof(si)
            si.StartupInfo.dwFlags = 0x00000100
            si.StartupInfo.hStdInput = sr.value
            si.StartupInfo.hStdOutput = rw.value
            si.StartupInfo.hStdError = rw.value
            si.lpAttributeList = C.cast(attrs, C.c_void_p)
            pi = PROCESS_INFORMATION()
            cmdline = C.create_unicode_buffer(subprocess.list2cmdline(argv))
            check(CreateProcess(None, cmdline, None, None, True, 0x00080000, None, cwd, C.byref(si), C.byref(pi)))
            self.process = pi.hProcess
            self.pid = pi.dwProcessId
            CloseHandle(pi.hThread)
            self.console_input, self.console_output = iw.value, ore.value
            self.input, self.output = sw.value, rr.value
            iw, ore = W.HANDLE(), W.HANDLE()
            sw, rr = W.HANDLE(), W.HANDLE()
        finally:
            if attrs is not None:
                DeleteAttrs(attrs)
            for h in (ir, iw, ore, ow, sr, sw, rr, rw):
                if h:
                    CloseHandle(h)
            if self.process is None and self.pc:
                ClosePseudoConsole(self.pc)
        self.reader = threading.Thread(target=self._read, args=(self.output,), daemon=True)
        self.console_reader = threading.Thread(target=self._read, args=(self.console_output,), daemon=True)
        self.writer = threading.Thread(target=self._write, daemon=True)
        self.reader.start()
        self.console_reader.start()
        self.writer.start()

    def _read(self, handle):
        buf = C.create_string_buffer(65536)
        count = W.DWORD()
        try:
            while ReadFile(handle, buf, len(buf), C.byref(count), None) and count.value:
                self.callback(buf.raw[:count.value])
        except Exception as exc:
            self.error = str(exc)

    def _write(self):
        try:
            while True:
                item = self.queue.get()
                if item is None:
                    return
                handle, chunk = item
                pos = 0
                while pos < len(chunk):
                    block = C.create_string_buffer(chunk[pos:pos + 8192])
                    count = W.DWORD()
                    check(WriteFile(handle, block, min(8192, len(chunk) - pos), C.byref(count), None))
                    if not count.value:
                        raise OSError('terminal input closed')
                    pos += count.value
        except Exception as exc:
            self.error = str(exc)

    def send(self, data):
        if self.closed or self.poll() is not None:
            raise ConnectionError('SSH terminal is not running')
        self.queue.put((self.input, data), timeout=10)

    def send_console(self, data):
        if self.closed or self.poll() is not None:
            raise ConnectionError('SSH terminal is not running')
        self.queue.put((self.console_input, data), timeout=10)

    def poll(self):
        if self.closed:
            return 0
        code = W.DWORD()
        check(GetExitCode(self.process, C.byref(code)))
        return None if code.value == 259 else code.value

    def close(self):
        if self.closed:
            return
        if self.poll() is None:
            TerminateProcess(self.process, 0)
        self.closed = True
        try:
            self.queue.put_nowait(None)
        except queue.Full:
            pass
        # Keep draining output while ClosePseudoConsole shuts down.
        ClosePseudoConsole(self.pc)
        for handle in (self.input, self.output, self.console_input, self.console_output, self.process):
            CloseHandle(handle)

