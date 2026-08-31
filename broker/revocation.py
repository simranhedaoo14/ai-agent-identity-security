import redis


class RevocationStore:

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379
    ):
        self.redis = redis.Redis(
            host=host,
            port=port,
            decode_responses=True
        )

    def revoke(self, grant_id: str):
        self.redis.set(
            f"revoked:{grant_id}",
            "1"
        )

    def is_revoked(
        self,
        grant_id: str
    ) -> bool:

        return bool(
            self.redis.exists(
                f"revoked:{grant_id}"
            )
        )