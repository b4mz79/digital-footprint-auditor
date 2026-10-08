from __future__ import annotations

import ctypes
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

from services.addon_runtime_worker import _MAX_RESPONSE_BYTES, _PROTOCOL_VERSION


_RUNTIME_EXECUTABLE_ENV = "ADDON_RUNTIME_EXECUTABLE"
_RUNTIME_TIMEOUT_ENV = "ADDON_RUNTIME_TIMEOUT_SECONDS"
_DEFAULT_TIMEOUT_SECONDS = 60.0
_AC_NAME_PREFIX = "PrivacyAuditorAddon_"
_AC_NAME_MAX = 64

_CREATE_NO_WINDOW = 0x08000000
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_STARTF_USESTDHANDLES = 0x00000100
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009

_WAIT_OBJECT_0 = 0x00000000
_WAIT_TIMEOUT = 0x00000102
_E_HR_ALREADY_EXISTS = 0x800700B7

_SID_TYPE = ctypes.c_void_p


class _SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", _SID_TYPE),
        ("Attributes", ctypes.c_uint32),
    ]


class _SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [
        ("AppContainerSid", _SID_TYPE),
        ("Capabilities", ctypes.POINTER(_SID_AND_ATTRIBUTES)),
        ("CapabilityCount", ctypes.c_uint32),
        ("Reserved", ctypes.c_uint32),
    ]


class _STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p),
        ("lpTitle", ctypes.c_wchar_p),
        ("dwX", ctypes.c_uint32),
        ("dwY", ctypes.c_uint32),
        ("dwXSize", ctypes.c_uint32),
        ("dwYSize", ctypes.c_uint32),
        ("dwXCountChars", ctypes.c_uint32),
        ("dwYCountChars", ctypes.c_uint32),
        ("dwFillAttribute", ctypes.c_uint32),
        ("dwFlags", ctypes.c_uint32),
        ("wShowWindow", ctypes.c_uint16),
        ("cbReserved2", ctypes.c_uint16),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", ctypes.c_void_p),
        ("hStdOutput", ctypes.c_void_p),
        ("hStdError", ctypes.c_void_p),
    ]


class _STARTUPINFOEX(ctypes.Structure):
    _fields_ = [
        ("StartupInfo", _STARTUPINFO),
        ("lpAttributeList", ctypes.c_void_p),
    ]


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", ctypes.c_void_p),
        ("hThread", ctypes.c_void_p),
        ("dwProcessId", ctypes.c_uint32),
        ("dwThreadId", ctypes.c_uint32),
    ]


def _runtime_timeout() -> float:
    raw = os.getenv(_RUNTIME_TIMEOUT_ENV, "").strip()
    if not raw:
        return _DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(
            "ADDON_RUNTIME_TIMEOUT_SECONDS must be numeric"
        ) from exc
    if value <= 0 or value > 900:
        raise ValueError(
            "ADDON_RUNTIME_TIMEOUT_SECONDS must be between 0 and 900 seconds"
        )
    return value


def _require_windows() -> None:
    if os.name != "nt":
        raise RuntimeError("AppContainer add-on runtime requires Windows")


def _userenv() -> Any:
    return ctypes.WinDLL("userenv", use_last_error=True)


def _kernel32() -> Any:
    return ctypes.WinDLL("kernel32", use_last_error=True)


def _advapi32() -> Any:
    return ctypes.WinDLL("advapi32", use_last_error=True)


def _ole32() -> Any:
    return ctypes.WinDLL("ole32", use_last_error=True)


def _configure_win32() -> None:
    userenv = _userenv()
    kernel32 = _kernel32()
    advapi32 = _advapi32()
    ole32 = _ole32()

    userenv.CreateAppContainerProfile.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_SID_AND_ATTRIBUTES),
        ctypes.c_uint32,
        ctypes.POINTER(_SID_TYPE),
    ]
    userenv.CreateAppContainerProfile.restype = ctypes.c_long

    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(_SID_TYPE),
    ]
    userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long

    userenv.GetAppContainerFolderPath.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    userenv.GetAppContainerFolderPath.restype = ctypes.c_long

    kernel32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.InitializeProcThreadAttributeList.restype = ctypes.c_int

    kernel32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    kernel32.UpdateProcThreadAttribute.restype = ctypes.c_int

    kernel32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    kernel32.DeleteProcThreadAttributeList.restype = None

    kernel32.CreateProcessW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(_STARTUPINFOEX),
        ctypes.POINTER(_PROCESS_INFORMATION),
    ]
    kernel32.CreateProcessW.restype = ctypes.c_int

    kernel32.WaitForSingleObject.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    kernel32.WaitForSingleObject.restype = ctypes.c_uint32

    kernel32.GetExitCodeProcess.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.GetExitCodeProcess.restype = ctypes.c_int

    kernel32.TerminateProcess.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
    ]
    kernel32.TerminateProcess.restype = ctypes.c_int

    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int

    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    advapi32.ConvertSidToStringSidW.argtypes = [
        _SID_TYPE,
        ctypes.POINTER(ctypes.c_wchar_p),
    ]
    advapi32.ConvertSidToStringSidW.restype = ctypes.c_int

    advapi32.ConvertStringSidToSidW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(_SID_TYPE),
    ]
    advapi32.ConvertStringSidToSidW.restype = ctypes.c_int

    ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    ole32.CoTaskMemFree.restype = None


def _win_error(prefix: str) -> OSError:
    error = ctypes.get_last_error()
    return OSError(error, f"{prefix} (WinError {error})")


def _create_or_derive_profile(name: str) -> tuple[str, Path]:
    _configure_win32()
    userenv = _userenv()
    sid = _SID_TYPE()

    hr = userenv.CreateAppContainerProfile(
        name,
        name,
        "Privacy Auditor untrusted add-on runtime",
        None,
        0,
        ctypes.byref(sid),
    )
    hr_u32 = ctypes.c_uint32(hr).value
    if hr != 0 and hr_u32 != _E_HR_ALREADY_EXISTS:
        raise OSError(
            "CreateAppContainerProfile failed: "
            f"HRESULT 0x{hr_u32:08X}"
        )

    if not sid.value:
        hr = userenv.DeriveAppContainerSidFromAppContainerName(
            name,
            ctypes.byref(sid),
        )
        if hr != 0:
            raise OSError(
                "DeriveAppContainerSidFromAppContainerName failed: "
                f"HRESULT 0x{ctypes.c_uint32(hr).value:08X}"
            )

    sid_text_ptr = ctypes.c_wchar_p()
    if not _advapi32().ConvertSidToStringSidW(
        sid,
        ctypes.byref(sid_text_ptr),
    ):
        raise _win_error("ConvertSidToStringSidW failed")

    try:
        sid_text = sid_text_ptr.value or ""
    finally:
        _kernel32().LocalFree(sid_text_ptr)

    if not sid_text:
        raise RuntimeError("AppContainer SID conversion returned an empty SID")

    folder_ptr = ctypes.c_wchar_p()
    hr = userenv.GetAppContainerFolderPath(
        sid_text,
        ctypes.byref(folder_ptr),
    )
    if hr != 0:
        raise OSError(
            "GetAppContainerFolderPath failed: "
            f"HRESULT 0x{ctypes.c_uint32(hr).value:08X}"
        )

    try:
        folder = Path(folder_ptr.value or "")
    finally:
        _ole32().CoTaskMemFree(folder_ptr)

    if not folder:
        raise RuntimeError("AppContainer profile path is empty")

    return sid_text, folder


def _profile_name(addon_id: str) -> str:
    safe = "".join(
        char if (char.isalnum() or char in "-_.") else "_"
        for char in addon_id
    )
    return f"{_AC_NAME_PREFIX}{safe}"[:_AC_NAME_MAX]


def _stage_request(
    profile_dir: Path,
    addon_root: Path,
    request: Mapping[str, Any],
) -> tuple[Path, Path]:
    runtime_dir = profile_dir / "PrivacyAuditorRuntime"
    if runtime_dir.exists():
        shutil.rmtree(runtime_dir, ignore_errors=True)
    runtime_dir.mkdir(parents=True, exist_ok=False)

    staged_addon = runtime_dir / "addon"
    shutil.copytree(addon_root, staged_addon)

    worker_source = Path(__file__).with_name("addon_runtime_worker.py")
    if not worker_source.is_file():
        raise FileNotFoundError(f"runtime worker not found: {worker_source}")
    worker_path = runtime_dir / "addon_runtime_worker.py"
    shutil.copy2(worker_source, worker_path)

    request_path = runtime_dir / "request.json"
    response_path = runtime_dir / "response.json"
    staged_request = dict(request)
    staged_request["package_root"] = str(staged_addon)
    staged_request["entrypoint"] = (
        str(request["entrypoint"]).replace("\\", "/")
    )
    request_path.write_text(
        json.dumps(
            staged_request,
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return request_path, response_path


def _safe_environment(profile_dir: Path) -> dict[str, str]:
    system_root = os.getenv("SystemRoot", r"C:\Windows")
    return {
        "SystemRoot": system_root,
        "WINDIR": os.getenv("WINDIR", system_root),
        "PATH": os.getenv("PATH", ""),
        "TEMP": str(profile_dir / "Temp"),
        "TMP": str(profile_dir / "Temp"),
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def _environment_block(environment: Mapping[str, str]) -> ctypes.Array:
    values = [
        f"{key}={value}"
        for key, value in sorted(environment.items())
        if key and "\x00" not in key and "\x00" not in value
    ]
    return ctypes.create_unicode_buffer("\x00".join(values) + "\x00\x00")


def _python_command(
    executable: Path,
    worker_path: Path,
    request_path: Path,
) -> str:
    if executable.suffix.lower() != ".exe":
        raise ValueError(
            f"runtime executable must be an .exe file: {executable}"
        )
    return subprocess.list2cmdline(
        [
            str(executable),
            "-I",
            "-B",
            str(worker_path),
            str(request_path),
        ]
    )


def _grant_read_execute(path: Path, sid_text: str) -> None:
    if not path.exists():
        raise FileNotFoundError(path)

    if path.is_dir():
        permissions = "(OI)(CI)RX"
        args = [
            "icacls",
            str(path),
            "/grant",
            f"*{sid_text}:{permissions}",
            "/T",
            "/C",
        ]
    else:
        args = [
            "icacls",
            str(path),
            "/grant",
            f"*{sid_text}:RX",
            "/C",
        ]

    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=False,
        creationflags=_CREATE_NO_WINDOW,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "icacls grant failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )


def _remove_access(path: Path, sid_text: str) -> None:
    if not path.exists():
        return

    args = [
        "icacls",
        str(path),
        "/remove",
        f"*{sid_text}",
        "/T",
        "/C",
    ]
    completed = subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=False,
        creationflags=_CREATE_NO_WINDOW,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "icacls remove failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )


def _launch_process(
    executable: Path,
    command_line: str,
    cwd: Path,
    response_path: Path,
    sid_text: str,
    environment: Mapping[str, str],
    timeout_seconds: float,
) -> int:
    _configure_win32()
    kernel32 = _kernel32()

    import msvcrt

    response_file = open(response_path, "w", encoding="utf-8")
    response_fd = response_file.fileno()
    os.set_handle_inheritable(response_fd, True)
    response_handle = ctypes.c_void_p(
        msvcrt.get_osfhandle(response_fd)
    )

    attribute_size = ctypes.c_size_t(0)
    kernel32.InitializeProcThreadAttributeList(
        None,
        2,
        0,
        ctypes.byref(attribute_size),
    )
    if attribute_size.value == 0:
        response_file.close()
        raise _win_error(
            "InitializeProcThreadAttributeList sizing failed"
        )

    attribute_buffer = ctypes.create_string_buffer(attribute_size.value)
    attribute_ptr = ctypes.cast(
        ctypes.byref(attribute_buffer),
        ctypes.c_void_p,
    )
    if not kernel32.InitializeProcThreadAttributeList(
        attribute_ptr,
        2,
        0,
        ctypes.byref(attribute_size),
    ):
        response_file.close()
        raise _win_error("InitializeProcThreadAttributeList failed")

    sid_buffer = _sid_from_string(sid_text)
    security_capabilities = _SECURITY_CAPABILITIES(
        AppContainerSid=sid_buffer,
        Capabilities=None,
        CapabilityCount=0,
        Reserved=0,
    )
    handle_list = (ctypes.c_void_p * 1)(response_handle.value)
    environment_block = _environment_block(environment)

    try:
        if not kernel32.UpdateProcThreadAttribute(
            attribute_ptr,
            0,
            _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(security_capabilities),
            ctypes.sizeof(security_capabilities),
            None,
            None,
        ):
            raise _win_error("UpdateProcThreadAttribute(security) failed")

        if not kernel32.UpdateProcThreadAttribute(
            attribute_ptr,
            0,
            _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.cast(handle_list, ctypes.c_void_p),
            ctypes.sizeof(handle_list),
            None,
            None,
        ):
            raise _win_error("UpdateProcThreadAttribute(handles) failed")

        startup = _STARTUPINFOEX()
        startup.StartupInfo.cb = ctypes.sizeof(_STARTUPINFOEX)
        startup.lpAttributeList = attribute_ptr
        startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
        startup.StartupInfo.hStdOutput = response_handle
        startup.StartupInfo.hStdError = response_handle

        process_info = _PROCESS_INFORMATION()
        command_buffer = ctypes.create_unicode_buffer(command_line)
        created = kernel32.CreateProcessW(
            str(executable),
            command_buffer,
            None,
            None,
            True,
            _EXTENDED_STARTUPINFO_PRESENT
            | _CREATE_NO_WINDOW
            | _CREATE_UNICODE_ENVIRONMENT,
            ctypes.cast(environment_block, ctypes.c_void_p),
            str(cwd),
            ctypes.byref(startup),
            ctypes.byref(process_info),
        )
        if not created:
            raise _win_error("CreateProcessW(AppContainer) failed")

        try:
            wait_result = kernel32.WaitForSingleObject(
                process_info.hProcess,
                int(timeout_seconds * 1000),
            )
            if wait_result == _WAIT_TIMEOUT:
                kernel32.TerminateProcess(process_info.hProcess, 124)
                kernel32.WaitForSingleObject(
                    process_info.hProcess,
                    5000,
                )
                raise TimeoutError(
                    f"add-on runtime exceeded {timeout_seconds:.1f} seconds"
                )
            if wait_result != _WAIT_OBJECT_0:
                raise _win_error("WaitForSingleObject failed")

            exit_code = ctypes.c_uint32()
            if not kernel32.GetExitCodeProcess(
                process_info.hProcess,
                ctypes.byref(exit_code),
            ):
                raise _win_error("GetExitCodeProcess failed")
            return int(exit_code.value)
        finally:
            kernel32.CloseHandle(process_info.hThread)
            kernel32.CloseHandle(process_info.hProcess)
    finally:
        kernel32.DeleteProcThreadAttributeList(attribute_ptr)
        response_file.close()
        _free_sid(sid_buffer)


def _sid_from_string(sid_text: str) -> _SID_TYPE:
    sid = _SID_TYPE()
    if not _advapi32().ConvertStringSidToSidW(
        sid_text,
        ctypes.byref(sid),
    ):
        raise _win_error("ConvertStringSidToSidW failed")
    return sid


def _free_sid(sid: _SID_TYPE) -> None:
    if sid.value:
        _kernel32().LocalFree(sid)


def _load_response(response_path: Path) -> dict[str, Any]:
    payload = response_path.read_bytes()
    if len(payload) > _MAX_RESPONSE_BYTES:
        raise ValueError("sandbox runtime response exceeds IPC limit")
    response = json.loads(payload.decode("utf-8"))
    if not isinstance(response, dict):
        raise ValueError("sandbox runtime response must be a JSON object")
    if response.get("protocol_version") != _PROTOCOL_VERSION:
        raise ValueError("unsupported sandbox runtime response protocol")
    return response


def execute_addon(
    addon_root: str | Path,
    *,
    entrypoint: str,
    function: str,
    context: Mapping[str, Any],
    addon_id: str,
) -> Any:
    """Execute one untrusted add-on call inside a Windows AppContainer."""
    _require_windows()
    if not isinstance(context, Mapping):
        raise TypeError("add-on runtime context must be a mapping")

    addon_path = Path(addon_root).resolve()
    if not addon_path.is_dir():
        raise ValueError(f"add-on package does not exist: {addon_path}")

    executable = Path(
        os.getenv(_RUNTIME_EXECUTABLE_ENV, sys.executable)
    ).resolve()
    if not executable.is_file():
        raise FileNotFoundError(
            f"add-on runtime executable does not exist: {executable}"
        )

    profile_name = _profile_name(addon_id)
    sid_text, profile_dir = _create_or_derive_profile(profile_name)
    profile_dir.mkdir(parents=True, exist_ok=True)
    (profile_dir / "Temp").mkdir(parents=True, exist_ok=True)

    request = {
        "protocol_version": _PROTOCOL_VERSION,
        "package_root": "",
        "entrypoint": entrypoint,
        "function": function,
        "context": dict(context),
    }

    request_path, response_path = _stage_request(
        profile_dir,
        addon_path,
        request,
    )

    runtime_root = executable.parent
    needs_runtime_acl = executable.name.lower().startswith("python")
    acl_target = runtime_root if needs_runtime_acl else executable

    try:
        _grant_read_execute(acl_target, sid_text)
        command_line = _python_command(
            executable,
            profile_dir / "PrivacyAuditorRuntime" / "addon_runtime_worker.py",
            request_path,
        )
        exit_code = _launch_process(
            executable,
            command_line,
            profile_dir / "PrivacyAuditorRuntime",
            response_path,
            sid_text,
            _safe_environment(profile_dir),
            _runtime_timeout(),
        )
        if not response_path.is_file():
            raise RuntimeError(
                f"sandbox runtime produced no response (exit={exit_code})"
            )

        response = _load_response(response_path)
        if not response.get("ok"):
            error = response.get("error")
            if isinstance(error, Mapping):
                raise RuntimeError(
                    f"add-on sandbox error: {error.get('type')}: "
                    f"{error.get('message')}"
                )
            raise RuntimeError(
                "add-on sandbox returned an unknown error"
            )
        return response.get("result")
    finally:
        _remove_access(acl_target, sid_text)
        shutil.rmtree(
            profile_dir / "PrivacyAuditorRuntime",
            ignore_errors=True,
        )
