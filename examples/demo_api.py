"""Deliberately flawed demo API. Run: uvicorn examples.demo_api:app --port 8000

Planted flaws (the tester should find each):
  * GET /admin/stats        - spec says secured, server never checks      -> authz critical
  * GET /users/{uid}/orders/{oid} - no ownership check                    -> BOLA critical
  * GET /items/{item_id}    - declares price: number but returns a string -> conformance
  * POST /items             - crashes (500) on a negative price           -> conformance
"""
import base64
import json
import os
import time
import uuid

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel

app = FastAPI(title="Demo API")
bearer = HTTPBearer(auto_error=False)  # declares security in the spec but enforces nothing

TOKENS = {"token-a": 1, "token-b": 2}  # fixed tokens, never expire
ORDERS = {(1, 10): {"id": 10, "user_id": 1, "total": 42.5}, (2, 20): {"id": 20, "user_id": 2, "total": 7.0}}

# Login with expiring JWTs, shaped like a typical auth service response. Demo credentials only.
USERS = {"alice@demo.test": ("alice-pass", 1), "bob@demo.test": ("bob-pass", 2)}
TOKEN_TTL = int(os.environ.get("DEMO_TOKEN_TTL", "45"))  # seconds; short on purpose to exercise refresh
ISSUED: dict[str, tuple[int, float]] = {}  # token -> (user id, expires at)
LOGINS = {"count": 0}


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


class Login(BaseModel):
    email: str
    password: str


@app.post("/auth/login", include_in_schema=False)
def login(body: Login):
    user = USERS.get(body.email)
    if not user or user[0] != body.password:
        raise HTTPException(401, "Invalid email or password")
    now = int(time.time())
    tok = ".".join([_b64({"alg": "none", "typ": "JWT"}),
                    _b64({"sub": user[1], "iat": now, "exp": now + TOKEN_TTL, "jti": uuid.uuid4().hex}), "sig"])
    ISSUED[tok] = (user[1], now + TOKEN_TTL)
    LOGINS["count"] += 1
    return {"success": True, "data": {"user": {"id": user[1], "email": body.email}, "accessToken": tok},
            "error": None}


@app.get("/auth/stats", include_in_schema=False)
def auth_stats():  # lets tests check how often the tester logged in
    return {"logins": LOGINS["count"], "ttl": TOKEN_TTL}


def current_user(creds=Depends(bearer)) -> int:
    if creds is None:
        raise HTTPException(401, "Unauthorized")
    if creds.credentials in TOKENS:
        return TOKENS[creds.credentials]
    issued = ISSUED.get(creds.credentials)
    if not issued:
        raise HTTPException(401, "Unauthorized")
    if time.time() >= issued[1]:
        raise HTTPException(401, "Token expired")
    return issued[0]


class Item(BaseModel):
    id: int
    name: str
    price: float
    in_stock: bool = True  # pydantic's lax mode accepts "true", 1, "yes" -> types stage should flag it


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/items/{item_id}", response_model=Item)
def get_item(item_id: int):
    if item_id == 7:
        # JSONResponse skips response_model validation, so the type violation reaches the client
        return JSONResponse({"id": 7, "name": "broken", "price": "free"})
    return Item(id=item_id, name=f"item-{item_id}", price=9.99)


@app.post("/items")
def create_item(item: Item):
    if item.price < 0:
        raise RuntimeError("negative price")
    return item


@app.get("/admin/stats", dependencies=[Depends(bearer)])
def admin_stats():
    return {"users": 2, "orders": 2}


@app.get("/users/{uid}/orders/{oid}")
def get_order(uid: int, oid: int, user: int = Depends(current_user)):
    order = ORDERS.get((uid, oid))
    if not order:
        raise HTTPException(404, "not found")
    return order  # BUG: never checks that `user` == uid
