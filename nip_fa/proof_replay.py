"""Single-use NIP-98 proofs on the agent routes (NIP-FA "Agent grant": the
adapter rejects a proof whose event `id` it already accepted on that route)."""

from redis.exceptions import RedisError

from .nip98 import MAX_AGE_SECONDS, MAX_FUTURE_SECONDS

# A proof dated MAX_FUTURE_SECONDS ahead stays acceptable for MAX_AGE_SECONDS
# after that, so its id must be remembered at least that long, plus a margin
# for clock drift between replicas sharing the record.
CLOCK_DRIFT_MARGIN_SECONDS = 30
PROOF_MEMORY_SECONDS = MAX_AGE_SECONDS + MAX_FUTURE_SECONDS + CLOCK_DRIFT_MARGIN_SECONDS


class ReplayGuardUnavailable(Exception):
    """The used-proof record could not be written."""


class ProofReplayGuard:
    KEY_PREFIX = "nip_fa_proof:"

    def __init__(self, redis_factory, route: str):
        self._redis_factory = redis_factory
        self._route = route

    def _key(self, event_id: str) -> str:
        return f"{self.KEY_PREFIX}{self._route}:{event_id}"

    async def first_use(self, event_id: str) -> bool:
        """Records the proof as used; False when it already was."""
        try:
            created = await self._redis_factory().set(self._key(event_id), "1", nx=True, ex=PROOF_MEMORY_SECONDS)
        except (RedisError, OSError) as exc:
            raise ReplayGuardUnavailable() from exc
        return bool(created)
