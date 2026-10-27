import hmac
import json
from pathlib import Path

from fastapi import Header, HTTPException
from safepatch.common import ROOT, digest, setting


def identity(authorization: str = Header(default="")):
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "Kullanıcı anahtarı gerekli")
    token_hash = digest(authorization[7:])
    users = json.loads(Path(setting("USERS_FILE", str(ROOT / ".secrets/users.json"))).read_text(encoding="utf-8"))
    user = next((u for u in users if hmac.compare_digest(u["token_sha256"], token_hash) and u.get("enabled", True)), None)
    if not user:
        raise HTTPException(401, "Geçersiz kullanıcı anahtarı")
    return {"subject": user["subject"], "roles": user["roles"], "projects": user.get("projects", ["owned-java-demo"])}


def require_role(user, role):
    if role not in user["roles"]:
        raise HTTPException(403, "Bu işlem için yetkiniz yok: " + role)
