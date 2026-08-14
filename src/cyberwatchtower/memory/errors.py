class MemoryErrorBase(RuntimeError):
    """Base class for classified Persistent Security Memory failures."""


class MemoryUnavailable(MemoryErrorBase):
    pass


class MemoryLocked(MemoryUnavailable):
    pass


class MemoryCorrupt(MemoryErrorBase):
    pass


class MemoryMigrationFailed(MemoryErrorBase):
    pass


class MemoryMigrationChecksumMismatch(MemoryMigrationFailed):
    pass


class MemoryIncompatibleVersion(MemoryErrorBase):
    pass


class MemoryIntegrityError(MemoryErrorBase):
    pass


class MemoryLifecycleError(MemoryErrorBase):
    pass


class MemoryQueryError(MemoryErrorBase):
    pass


class MemoryDecisionError(MemoryErrorBase):
    pass
