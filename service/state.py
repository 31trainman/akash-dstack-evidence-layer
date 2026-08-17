from dataclasses import dataclass
import secrets, threading, time
@dataclass
class ChallengeRecord:
    challenge_id: str
    nonce: bytes
    policy_id: str
    require_gpu: bool
    expires_at: float
    used: bool=False
class ChallengeStore:
    def __init__(self,ttl_seconds=120): self.ttl_seconds=ttl_seconds; self._lock=threading.Lock(); self._items={}
    def issue(self,policy_id,require_gpu=False):
        r=ChallengeRecord(secrets.token_urlsafe(24),secrets.token_bytes(32),policy_id,require_gpu,time.time()+self.ttl_seconds)
        with self._lock: self._items[r.challenge_id]=r
        return r
    def consume(self,challenge_id,nonce):
        with self._lock:
            r=self._items.get(challenge_id)
            if r is None: raise ValueError('unknown challenge')
            if r.used: raise ValueError('challenge already used')
            if time.time()>r.expires_at: raise ValueError('challenge expired')
            if not secrets.compare_digest(r.nonce,nonce): raise ValueError('nonce mismatch')
            r.used=True
            return r
