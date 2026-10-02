"""Deliberately flawed demo API. Run: uvicorn examples.demo_api:app --port 8000

Planted flaws (the tester should find each):
  * GET /admin/stats        - spec says secured, server never checks      -> authz critical
  * GET /users/{uid}/orders/{oid} - no ownership check                    -> BOLA critical
  * GET /items/{item_id}    - declares price: number but returns a string -> conformance
  * POST /items             - crashes (500) on a negative price           -> conformance
"""
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel

app = FastAPI(title="Demo API")
bearer = HTTPBearer(auto_error=False)  # declares security in the spec but enforces nothing

TOKENS = {"token-a": 1, "token-b": 2}
ORDERS = {(1, 10): {"id": 10, "user_id": 1, "total": 42.5}, (2, 20): {"id": 20, "user_id": 2, "total": 7.0}}


def current_user(creds=Depends(bearer)) -> int:
    if creds is None or creds.credentials not in TOKENS:
        raise HTTPException(401, "Unauthorized")
    return TOKENS[creds.credentials]


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
