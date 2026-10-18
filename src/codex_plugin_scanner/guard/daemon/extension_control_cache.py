"""Release expired preview cache leases using native unpin planning."""

from __future__ import annotations

import time

from ..catalog_delivery import lifecycle


def expire(service):
    # Serialize with both preview and apply, including an apply that crossed its
    # original expiry check. Expired proof records keep their existing response.
    with service._preview_lock, service._apply_lock, service._proof_lock:
        candidates = list(service._candidates.values.values())
        candidates.extend(item.candidate for item in service._pending_proofs.values())
        response = lifecycle.invoke(
            "offline",
            operation="expired-leases",
            now=time.monotonic(),
            expires=[None if item is None else item.expires_at for item in candidates],
        )
        for index in response["expired"]:
            candidates[index].draft._cache_lease.close()
