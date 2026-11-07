"""Explicit Win32 security for private stores; never rely on POSIX mode emulation.

New paths get a current-user owner and protected, inheritable DACL at creation.
Existing objects are inspected, never repaired. Pathname traversal still requires
trusted ancestors; this module does not claim handle-relative namespace safety.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


def acl_is_private(aces: list[tuple[int, int, str]], user: str) -> bool:
    """Reject unknown ACE forms and nonzero grants to unrelated principals.

    Plain deny ACEs only restrict access. Inherit-only grants are deliberately
    included: they can expose subsequently created SQLite sidecars.
    """
    allowed = {user, "S-1-5-18", "S-1-5-32-544"}  # user, SYSTEM, Administrators
    return all(kind == 1 or (kind == 0 and (mask == 0 or sid in allowed))
               for kind, mask, sid in aces)


class _SecurityAttributes(ctypes.Structure):
    """Win32 SECURITY_ATTRIBUTES with pointer-width-correct fields."""

    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                ("bInheritHandle", wintypes.BOOL)]


class WindowsSecurity:
    """Bind the exact Win32 ABI and own all allocated security buffers/handles."""

    def __init__(self) -> None:
        """Load native libraries and bind every called function before use."""
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        ptr = ctypes.c_void_p
        pptr = ctypes.POINTER(ptr)
        dwordp = ctypes.POINTER(wintypes.DWORD)
        self._bind(self.kernel, "GetCurrentProcess", wintypes.HANDLE, [])
        self._bind(self.kernel, "CloseHandle", wintypes.BOOL, [wintypes.HANDLE])
        self._bind(self.kernel, "LocalFree", ptr, [ptr])
        self._bind(self.kernel, "CreateDirectoryW", wintypes.BOOL,
                   [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)])
        self._bind(self.kernel, "CreateFileW", wintypes.HANDLE,
                   [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                    ctypes.POINTER(_SecurityAttributes), wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE])
        self._bind(self.advapi, "OpenProcessToken", wintypes.BOOL,
                   [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)])
        self._bind(self.advapi, "GetTokenInformation", wintypes.BOOL,
                   [wintypes.HANDLE, ctypes.c_int, ptr, wintypes.DWORD, dwordp])
        self._bind(self.advapi, "ConvertSidToStringSidW", wintypes.BOOL, [ptr, pptr])
        self._bind(self.advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", wintypes.BOOL,
                   [wintypes.LPCWSTR, wintypes.DWORD, pptr, dwordp])
        self._bind(self.advapi, "GetNamedSecurityInfoW", wintypes.DWORD,
                   [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, pptr, pptr, pptr, pptr, pptr])
        self._bind(self.advapi, "GetSecurityInfo", wintypes.DWORD,
                   [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, pptr, pptr, pptr, pptr, pptr])
        self._bind(self.advapi, "IsValidAcl", wintypes.BOOL, [ptr])
        self._bind(self.advapi, "GetAce", wintypes.BOOL, [ptr, wintypes.DWORD, pptr])
        self.user = self._token_user()

    @staticmethod
    def _bind(library: Any, name: str, result: Any, arguments: list[Any]) -> None:
        """Declare result and parameter widths without swallowing ABI failures."""
        function = getattr(library, name)
        function.restype = result
        function.argtypes = arguments

    def _sid_text(self, sid: ctypes.c_void_p) -> str:
        """Copy a native SID string before releasing its LocalAlloc buffer."""
        text = ctypes.c_void_p()
        if not self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return ctypes.wstring_at(text)
        finally:
            self.kernel.LocalFree(text)

    def _token_user(self) -> str:
        """Read TokenUser, not the elevated token's potentially different owner."""
        token = wintypes.HANDLE()
        if not self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            length = wintypes.DWORD()
            self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
            if not length.value:
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = ctypes.create_string_buffer(length.value)
            if not self.advapi.GetTokenInformation(token, 1, buffer, length, ctypes.byref(length)):
                raise ctypes.WinError(ctypes.get_last_error())
            sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p)).contents
            return self._sid_text(sid)
        finally:
            self.kernel.CloseHandle(token)

    @contextmanager
    def _attributes(self) -> Iterator[_SecurityAttributes]:
        """Build an explicit user owner and protected ACL before creating objects."""
        descriptor = ctypes.c_void_p()
        sddl = (f"O:{self.user}D:P(A;OICI;FA;;;{self.user})"
                "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
        if not self.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        finally:
            self.kernel.LocalFree(descriptor)

    def create_directory(self, path: Path) -> None:
        """Create only the final directory, atomically applying owner and DACL."""
        with self._attributes() as attributes:
            if not self.kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                raise ctypes.WinError(ctypes.get_last_error())

    def create_file(self, path: Path) -> None:
        """Use CREATE_NEW with explicit security and inspect the actual opened handle."""
        with self._attributes() as attributes:
            handle = self.kernel.CreateFileW(
                str(path), 0xC0020000, 0, ctypes.byref(attributes), 1, 0x00200000, None
            )  # GENERIC_READ/WRITE + READ_CONTROL, CREATE_NEW, OPEN_REPARSE_POINT
            creation_error = ctypes.get_last_error()
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(creation_error)
        try:
            if not self.private_acl(path, handle=handle):
                raise PermissionError("created store failed handle security validation")
        finally:
            self.kernel.CloseHandle(handle)

    def private_acl(self, path: Path, *, handle: Any = None) -> bool:
        """Require current-user ownership and no effective or inherited foreign grants."""
        owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
        arguments = (1, 0x00000005, ctypes.byref(owner), None, ctypes.byref(dacl),
                     None, ctypes.byref(descriptor))  # SE_FILE_OBJECT, OWNER | DACL
        if handle is None:
            result = self.advapi.GetNamedSecurityInfoW(str(path), *arguments)
        else:
            result = self.advapi.GetSecurityInfo(handle, *arguments)
        try:
            if result or not owner.value or not dacl.value:
                return False  # NULL DACL permits everyone
            if self._sid_text(owner) != self.user or not self.advapi.IsValidAcl(dacl):
                return False
            # ACL header: revision/size are bytes 0..3, AceCount is uint16 at 4.
            count = ctypes.c_uint16.from_address(dacl.value + 4).value
            aces: list[tuple[int, int, str]] = []
            for index in range(count):
                ace = ctypes.c_void_p()
                if not self.advapi.GetAce(dacl, index, ctypes.byref(ace)) or not ace.value:
                    return False
                kind = ctypes.c_ubyte.from_address(ace.value).value
                size = ctypes.c_uint16.from_address(ace.value + 2).value
                if kind not in (0, 1) or size < 16:
                    return False  # unsupported/object/callback ACEs fail closed
                mask = ctypes.c_uint32.from_address(ace.value + 4).value
                sid = self._sid_text(ctypes.c_void_p(ace.value + 8))
                aces.append((kind, mask, sid))
            return acl_is_private(aces, self.user)
        finally:
            if descriptor.value:
                self.kernel.LocalFree(descriptor)
