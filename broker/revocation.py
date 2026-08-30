class RevocationStore:

    def __init__(self):
        self.revoked_grants = set()

    def revoke(self, grant_id: str):
        self.revoked_grants.add(grant_id)

    def is_revoked(self, grant_id: str) -> bool:
        return grant_id in self.revoked_grants