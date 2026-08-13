import re
from pathlib import Path


MAX_CMDLINE_BYTES = 64 * 1024

INTERPRETER_PATTERNS = {
    "bash": re.compile(r"^bash(?:\d+(?:\.\d+)*)?$"),
    "java": re.compile(r"^java(?:\d+(?:\.\d+)*)?$"),
    "node": re.compile(r"^(?:node|nodejs)(?:\d+(?:\.\d+)*)?$"),
    "perl": re.compile(r"^perl(?:\d+(?:\.\d+)*)?$"),
    "python": re.compile(r"^python(?:\d+(?:\.\d+)*)?$"),
    "ruby": re.compile(r"^ruby(?:\d+(?:\.\d+)*)?$"),
    "sh": re.compile(r"^(?:sh|dash)$"),
}

KNOWN_APPLICATIONS = {
    "wsdd": "WSDD",
}


def _interpreter_family(process_name: str) -> str | None:
    executable_name = Path(process_name).name.casefold()

    for family, pattern in INTERPRETER_PATTERNS.items():
        if pattern.fullmatch(executable_name):
            return family

    return None


def _read_cmdline(pid: int, proc_root: Path) -> tuple[list[str] | None, str | None]:
    cmdline_path = proc_root / str(pid) / "cmdline"

    try:
        with cmdline_path.open("rb") as file:
            raw_cmdline = file.read(MAX_CMDLINE_BYTES + 1)
    except FileNotFoundError:
        return None, "process_not_found"
    except PermissionError:
        return None, "permission_denied"
    except OSError:
        return None, "unreadable"

    if len(raw_cmdline) > MAX_CMDLINE_BYTES:
        return None, "cmdline_too_large"

    arguments = [
        value.decode("utf-8", errors="replace")
        for value in raw_cmdline.split(b"\0")
        if value
    ]

    if not arguments:
        return None, "empty_cmdline"

    return arguments, None


def _python_application(arguments: list[str]) -> str | None:
    index = 1

    while index < len(arguments):
        argument = arguments[index]

        if argument in {"-c", "-"}:
            return None
        if argument == "-m":
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument in {"-W", "-X"}:
            index += 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        return argument

    return None


def _script_application(
    arguments: list[str], inline_code_flags: set[str], value_flags: set[str]
) -> str | None:
    index = 1

    while index < len(arguments):
        argument = arguments[index]

        if argument in inline_code_flags:
            return None
        if argument in value_flags:
            index += 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        return argument

    return None


def _java_application(arguments: list[str]) -> str | None:
    value_flags = {
        "--class-path",
        "--module-path",
        "--upgrade-module-path",
        "-classpath",
        "-cp",
        "-p",
    }
    index = 1

    while index < len(arguments):
        argument = arguments[index]

        if argument == "-jar":
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if argument in value_flags:
            index += 2
            continue
        if argument.startswith("-"):
            index += 1
            continue
        return argument

    return None


def _application_from_arguments(
    interpreter: str, arguments: list[str]
) -> str | None:
    if interpreter == "python":
        return _python_application(arguments)
    if interpreter in {"bash", "sh"}:
        return _script_application(
            arguments,
            {"-c"},
            {"--init-file", "--rcfile", "-O", "-o"},
        )
    if interpreter == "node":
        return _script_application(
            arguments,
            {"--eval", "--print", "-e", "-p"},
            {"--import", "--loader", "--require", "-r"},
        )
    if interpreter == "ruby":
        return _script_application(arguments, {"-e"}, {"-C", "-E", "-F", "-I", "-r"})
    if interpreter == "perl":
        return _script_application(arguments, {"-E", "-e"}, {"-I", "-m", "-M"})
    if interpreter == "java":
        return _java_application(arguments)
    return None


def _application_name(application: str) -> tuple[str, bool]:
    application_basename = Path(application).name
    normalized_name = application_basename.casefold()

    if normalized_name in KNOWN_APPLICATIONS:
        return KNOWN_APPLICATIONS[normalized_name], True

    if normalized_name.endswith(".jar"):
        application_basename = application_basename[:-4]

    return application_basename or application, False


def inspect_process_application(
    pid: int | None,
    process_name: str,
    proc_root: str | Path = "/proc",
) -> dict:
    """Identify an interpreter-backed application without returning raw argv."""

    interpreter = _interpreter_family(process_name)

    result = {
        "inspected": False,
        "interpreter": interpreter,
        "application": None,
        "application_name": None,
        "known_application": False,
        "reason": None,
    }

    if interpreter is None:
        result["reason"] = "not_interpreter"
        return result

    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        result["reason"] = "invalid_pid"
        return result

    arguments, error = _read_cmdline(pid, Path(proc_root))

    if error:
        result["reason"] = error
        return result

    if _interpreter_family((arguments or [""])[0]) != interpreter:
        result["reason"] = "process_changed"
        return result

    result["inspected"] = True
    application = _application_from_arguments(interpreter, arguments or [])

    if not application:
        result["reason"] = "application_not_identified"
        return result

    application_name, known_application = _application_name(application)
    result.update(
        {
            "application": application,
            "application_name": application_name,
            "known_application": known_application,
        }
    )
    return result
