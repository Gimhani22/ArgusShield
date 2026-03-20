"""
PipeListenerThread — connects to the ArgusShield Agent named pipe
(\\.\pipe\ArgusShieldAgent) and emits Qt signals when injection
alerts or image-load events arrive.
"""

import time
import struct
from PyQt5.QtCore import QThread, pyqtSignal


# On Windows the named pipe path uses the UNC-style prefix.
AGENT_PIPE = r'\\.\pipe\ArgusShieldAgent'


def _connect_pipe(path: str):
    """Open a named-pipe client handle using ctypes (win32 API)."""
    import ctypes
    import ctypes.wintypes as wt

    GENERIC_READ    = 0x80000000
    OPEN_EXISTING   = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    INVALID_HANDLE  = wt.HANDLE(-1).value & 0xFFFFFFFFFFFFFFFF

    kernel32 = ctypes.windll.kernel32

    handle = kernel32.CreateFileW(
        path,
        GENERIC_READ,
        0,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        None,
    )

    # Normalise to unsigned for comparison
    if (handle & 0xFFFFFFFFFFFFFFFF) == INVALID_HANDLE:
        return None

    # Switch to message-read mode
    PIPE_READMODE_MESSAGE = 0x00000002
    mode = wt.DWORD(PIPE_READMODE_MESSAGE)
    kernel32.SetNamedPipeHandleState(handle, ctypes.byref(mode), None, None)

    return handle


def _read_pipe(handle) -> bytes:
    """Read one chunk from the pipe. Returns b'' on disconnect."""
    import ctypes
    import ctypes.wintypes as wt

    buf = ctypes.create_string_buffer(4096)
    bytes_read = wt.DWORD(0)
    ok = ctypes.windll.kernel32.ReadFile(
        handle, buf, 4096, ctypes.byref(bytes_read), None
    )
    if not ok or bytes_read.value == 0:
        return b''
    return buf.raw[: bytes_read.value]


def _close_handle(handle):
    import ctypes
    ctypes.windll.kernel32.CloseHandle(handle)


class PipeListenerThread(QThread):
    """Background thread that listens on the Agent pipe.

    Signals
    -------
    alert_received(dict)
        Emitted when an ``InjectionAlert|…`` message arrives.
        The dict contains ``target_pid``, ``dll_path``, ``technique``,
        ``severity`` parsed from the pipe message.

    image_load_received(dict)
        Emitted when an ``ImageLoad|…`` event arrives.
        The dict contains ``pid``, ``base``, ``size``, ``path``.

    connection_changed(bool)
        Emitted when the pipe connects (True) or disconnects (False).
    """

    alert_received      = pyqtSignal(dict)
    image_load_received = pyqtSignal(dict)
    connection_changed  = pyqtSignal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = True

    def stop(self):
        self._running = False

    # ── main loop ───────────────────────────────────────────────────────

    def run(self):
        while self._running:
            handle = _connect_pipe(AGENT_PIPE)
            if handle is None:
                time.sleep(2)
                continue

            self.connection_changed.emit(True)
            pending = ''

            try:
                while self._running:
                    data = _read_pipe(handle)
                    if not data:
                        break
                    pending += data.decode('utf-8', errors='replace')

                    while '\n' in pending:
                        line, pending = pending.split('\n', 1)
                        line = line.strip()
                        if line:
                            self._dispatch(line)
            finally:
                _close_handle(handle)
                self.connection_changed.emit(False)

            time.sleep(2)   # wait before reconnecting

    # ── message dispatch ────────────────────────────────────────────────

    def _dispatch(self, line: str):
        if line.startswith('InjectionAlert|'):
            self.alert_received.emit(self._parse_fields(line))
        elif line.startswith('ImageLoad|'):
            self.image_load_received.emit(self._parse_fields(line))

    @staticmethod
    def _parse_fields(line: str) -> dict:
        result = {}
        for token in line.split('|'):
            if '=' in token:
                key, value = token.split('=', 1)
                result[key] = value
        return result
