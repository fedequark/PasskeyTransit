from __future__ import annotations

from collections.abc import Callable

from .cxf_subset import export_subset, import_subset
from .model import SyntheticPasskey


Provider = Callable[[SyntheticPasskey], SyntheticPasskey]


def strict(credential: SyntheticPasskey) -> SyntheticPasskey:
    return import_subset(export_subset(credential))


def permissive(credential: SyntheticPasskey) -> SyntheticPasskey:
    migrated = import_subset(export_subset(credential))
    # A deliberate policy control: largeBlob is accepted only up to 48 bytes.
    if migrated.large_blob is not None and len(migrated.large_blob) > 48:
        migrated = migrated.evolve(large_blob=None)
    return migrated


def legacy(credential: SyntheticPasskey) -> SyntheticPasskey:
    migrated = import_subset(export_subset(credential))
    return migrated.evolve(prf_secret=None, large_blob=None)


PROVIDERS: dict[str, Provider] = {
    "strict": strict,
    "permissive": permissive,
    "legacy": legacy,
}


def migrate_route(
    credential: SyntheticPasskey, route: list[str]
) -> SyntheticPasskey:
    current = credential
    for provider_name in route:
        try:
            provider = PROVIDERS[provider_name]
        except KeyError as exc:
            raise ValueError(f"unknown provider policy: {provider_name}") from exc
        current = provider(current)
    return current

