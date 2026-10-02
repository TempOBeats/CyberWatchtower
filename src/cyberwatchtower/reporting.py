import errno
import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .finding_identity import finding_identity
from .report_contracts import (
    CURRENT_REPORT_SCHEMA_VERSION,
    assessment_assurance_summary,
    normalize_assessment_domains,
    normalize_coverage,
)
from .scoring_report import serialize_security_score


_MAX_REPORT_PATH_CANDIDATES = 1000
_TEMP_REPORT_PREFIX = ".cyberwatchtower-report-"
_TEMP_REPORT_SUFFIX = ".tmp"
_SOURCE_HANDLE_DIRECTORY = Path("/proc/self/fd")
_OBJECT_BOUND_PUBLICATION_SUPPORTED = (
    hasattr(os, "O_DIRECTORY")
    and hasattr(os, "O_NOFOLLOW")
    and os.link in os.supports_dir_fd
    and os.link in os.supports_follow_symlinks
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
    and os.unlink in os.supports_dir_fd
)
_SOURCE_BOUND_PUBLICATION_SUPPORTED = (
    os.name == "posix" and _OBJECT_BOUND_PUBLICATION_SUPPORTED
)


class _CanonicalNameExhausted(FileExistsError):
    """Identify only exhaustion of the frozen canonical-name candidates."""


@dataclass(slots=True)
class _PublicationReceipt:
    """Private physical identity retained from secure canonical publication."""

    path: Path
    canonical_name: str
    directory_descriptor: int
    directory_device: int
    directory_inode: int
    file_device: int
    file_inode: int
    file_size: int
    content_sha256: bytes
    resolved_directory: Path | None

    def close(self) -> None:
        descriptor = self.directory_descriptor
        self.directory_descriptor = -1
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _directory_identity(value):
    device = value.st_dev
    inode = value.st_ino
    if (
        not isinstance(device, int)
        or isinstance(device, bool)
        or device < 0
        or not isinstance(inode, int)
        or isinstance(inode, bool)
        or inode <= 0
    ):
        raise OSError(
            errno.ENOTSUP,
            "Secure report publication is unavailable.",
        )
    return device, inode


def _open_report_directory(report_dir):
    if not _OBJECT_BOUND_PUBLICATION_SUPPORTED:
        raise OSError(
            errno.ENOTSUP,
            "Secure report publication is unavailable.",
        )
    initial = report_dir.lstat()
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISDIR(initial.st_mode):
        raise OSError(errno.ENOTDIR, "Report directory is not a safe directory.")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(report_dir, flags)
    try:
        opened = os.fstat(descriptor)
        identity = _directory_identity(opened)
        if not stat.S_ISDIR(opened.st_mode):
            raise OSError(
                errno.ENOTDIR,
                "Report directory is not a safe directory.",
            )
        _revalidate_report_directory(report_dir, descriptor, identity)
        return descriptor, identity
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_source_handle_directory():
    if not _SOURCE_BOUND_PUBLICATION_SUPPORTED:
        raise OSError(
            errno.ENOTSUP,
            "Source-bound report publication is unavailable.",
        )
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        descriptor = os.open(_SOURCE_HANDLE_DIRECTORY, flags)
    except OSError as exc:
        raise OSError(
            errno.ENOTSUP,
            "Source-bound report publication is unavailable.",
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISDIR(opened.st_mode):
            raise OSError(
                errno.ENOTSUP,
                "Source-bound report publication is unavailable.",
            )
        return descriptor
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _revalidate_report_directory(report_dir, descriptor, identity):
    try:
        current = report_dir.lstat()
        opened = os.fstat(descriptor)
        repeated = report_dir.lstat()
    except OSError as exc:
        raise OSError(
            errno.EIO,
            "Report directory identity could not be verified.",
        ) from exc
    if (
        stat.S_ISLNK(current.st_mode)
        or not stat.S_ISDIR(current.st_mode)
        or stat.S_ISLNK(repeated.st_mode)
        or not stat.S_ISDIR(repeated.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or _directory_identity(current) != identity
        or _directory_identity(opened) != identity
        or _directory_identity(repeated) != identity
    ):
        raise OSError(
            errno.EIO,
            "Report directory identity changed during publication.",
        )


def _entry_identity(value):
    return value.st_dev, value.st_ino


def _verify_temp_entry(directory_descriptor, temp_name, temp_identity):
    try:
        current = os.stat(
            temp_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise OSError(
            errno.EIO,
            "Temporary report identity could not be verified.",
        ) from exc
    if (
        not stat.S_ISREG(current.st_mode)
        or _entry_identity(current) != temp_identity
    ):
        raise OSError(
            errno.EIO,
            "Temporary report identity changed during publication.",
        )


def _verify_source_handle(
    source_handle_directory_descriptor,
    temp_descriptor,
    temp_identity,
):
    try:
        opened = os.fstat(temp_descriptor)
        source = os.stat(
            str(temp_descriptor),
            dir_fd=source_handle_directory_descriptor,
            follow_symlinks=True,
        )
    except OSError as exc:
        raise OSError(
            errno.EIO,
            "Temporary report handle could not be verified.",
        ) from exc
    if (
        not stat.S_ISREG(opened.st_mode)
        or not stat.S_ISREG(source.st_mode)
        or _entry_identity(opened) != temp_identity
        or _entry_identity(source) != temp_identity
    ):
        raise OSError(
            errno.EIO,
            "Temporary report handle identity changed during publication.",
        )


def _cleanup_temp(directory_descriptor, temp_name):
    if temp_name is None:
        return
    try:
        os.unlink(temp_name, dir_fd=directory_descriptor)
    except OSError:
        pass


def _report_candidate_name(base_report_path, collision_number):
    if collision_number == 0:
        return base_report_path.name
    return f"{base_report_path.stem}_{collision_number}{base_report_path.suffix}"


def _publish_serialized_report(
    report_dir,
    base_report_path,
    payload,
    *,
    retain_directory=False,
):
    directory_descriptor, directory_identity = _open_report_directory(report_dir)
    source_handle_directory_descriptor = -1
    temp_descriptor = -1
    stream_descriptor = -1
    temp_name = None
    published_name = None
    retained_directory_descriptor = -1
    try:
        resolved_directory = None
        if retain_directory:
            resolved_directory = report_dir.resolve(strict=True)
            _revalidate_report_directory(
                report_dir,
                directory_descriptor,
                directory_identity,
            )
        source_handle_directory_descriptor = _open_source_handle_directory()
        temp_descriptor, temp_path = tempfile.mkstemp(
            prefix=_TEMP_REPORT_PREFIX,
            suffix=_TEMP_REPORT_SUFFIX,
            dir=report_dir,
        )
        temp_name = Path(temp_path).name
        temp_stat = os.fstat(temp_descriptor)
        if not stat.S_ISREG(temp_stat.st_mode):
            raise OSError(errno.EIO, "Temporary report is not a regular file.")
        temp_identity = _entry_identity(temp_stat)
        _verify_temp_entry(directory_descriptor, temp_name, temp_identity)

        stream_descriptor = os.dup(temp_descriptor)
        stream = os.fdopen(stream_descriptor, "w", encoding="utf-8")
        stream_descriptor = -1
        with stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())

        _revalidate_report_directory(
            report_dir,
            directory_descriptor,
            directory_identity,
        )
        _verify_temp_entry(directory_descriptor, temp_name, temp_identity)
        _verify_source_handle(
            source_handle_directory_descriptor,
            temp_descriptor,
            temp_identity,
        )
        source_handle_name = str(temp_descriptor)

        for collision_number in range(_MAX_REPORT_PATH_CANDIDATES):
            candidate_name = _report_candidate_name(
                base_report_path,
                collision_number,
            )
            try:
                os.link(
                    source_handle_name,
                    candidate_name,
                    src_dir_fd=source_handle_directory_descriptor,
                    dst_dir_fd=directory_descriptor,
                    follow_symlinks=True,
                )
            except FileExistsError:
                continue
            published_name = candidate_name
            break
        else:
            raise _CanonicalNameExhausted(
                errno.EEXIST,
                "No canonical report filename is available.",
            )

        _revalidate_report_directory(
            report_dir,
            directory_descriptor,
            directory_identity,
        )
        published_stat = os.stat(
            published_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(published_stat.st_mode)
            or _entry_identity(published_stat) != temp_identity
        ):
            raise OSError(
                errno.EIO,
                "Published report identity could not be verified.",
            )
        if retain_directory:
            retained_directory_descriptor = os.dup(directory_descriptor)
            retained_directory_stat = os.fstat(retained_directory_descriptor)
            if (
                not stat.S_ISDIR(retained_directory_stat.st_mode)
                or _directory_identity(retained_directory_stat)
                != directory_identity
            ):
                raise OSError(
                    errno.EIO,
                    "Published report directory identity could not be retained.",
                )

        os.unlink(temp_name, dir_fd=directory_descriptor)
        temp_name = None
        receipt = _PublicationReceipt(
            path=report_dir / published_name,
            canonical_name=published_name,
            directory_descriptor=retained_directory_descriptor,
            directory_device=directory_identity[0],
            directory_inode=directory_identity[1],
            file_device=published_stat.st_dev,
            file_inode=published_stat.st_ino,
            file_size=published_stat.st_size,
            content_sha256=hashlib.sha256(payload.encode("utf-8")).digest(),
            resolved_directory=resolved_directory,
        )
        retained_directory_descriptor = -1
        return receipt
    finally:
        if stream_descriptor >= 0:
            try:
                os.close(stream_descriptor)
            except OSError:
                pass
        if temp_descriptor >= 0:
            try:
                os.close(temp_descriptor)
            except OSError:
                pass
        _cleanup_temp(directory_descriptor, temp_name)
        if source_handle_directory_descriptor >= 0:
            try:
                os.close(source_handle_directory_descriptor)
            except OSError:
                pass
        try:
            os.close(directory_descriptor)
        except OSError:
            pass
        if retained_directory_descriptor >= 0:
            try:
                os.close(retained_directory_descriptor)
            except OSError:
                pass


def finding_to_dict(finding):
    data = {
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity.value,
        "recommendation": finding.recommendation,
        "evidence": finding.evidence,
        "confidence": finding.confidence,
        "technique_id": finding.technique_id,
        "source": finding.source,
        "kind": finding.kind.value,
        "assessment_state": finding.assessment_state.value,
        "runtime_instance_count": finding.runtime_instance_count,
    }

    data["finding_id"] = finding.finding_id or finding_identity(data)
    if finding.network_context is not None:
        data["network_context"] = finding.network_context

    return data


def _save_json_report(results, report_directory, *, retain_directory):
    report_dir = Path(report_directory)
    report_dir.mkdir(parents=True, exist_ok=True)

    now = datetime.now().astimezone()
    timestamp = now.strftime("%Y%m%d_%H%M%S_%f")

    hostname = results["system"].get("hostname", "unknown")
    safe_hostname = "".join(
        char if char.isalnum() or char in "-_" else "_"
        for char in hostname
    )

    base_report_path = report_dir / (
        f"cyberwatchtower_{safe_hostname}_{timestamp}.json"
    )

    assessment_domains = normalize_assessment_domains(
        results.get("assessment_domains")
    )
    coverage = normalize_coverage(results.get("coverage"), assessment_domains)
    serialized_findings = [
        finding_to_dict(finding)
        for finding in results["findings"]
    ]
    report_finding_ids = {
        finding["finding_id"] for finding in serialized_findings
    }
    report = {
        "schema_version": CURRENT_REPORT_SCHEMA_VERSION,
        "generated_at": now.isoformat(),
        "system": results["system"],
        "assessment_domains": [domain.value for domain in assessment_domains],
        "coverage": coverage,
        "assessment_assurance": assessment_assurance_summary(
            coverage, assessment_domains
        ),
        "security_score": serialize_security_score(
            results["score"], report_finding_ids
        ),
        "findings": serialized_findings,
    }

    serialized_report = json.dumps(report, indent=2)
    return _publish_serialized_report(
        report_dir,
        base_report_path,
        serialized_report,
        retain_directory=retain_directory,
    )


def _save_json_report_with_receipt(results, report_directory="reports"):
    return _save_json_report(
        results,
        report_directory,
        retain_directory=True,
    )


def save_json_report(results, report_directory="reports"):
    receipt = _save_json_report(
        results,
        report_directory,
        retain_directory=False,
    )
    try:
        return receipt.path
    finally:
        receipt.close()
