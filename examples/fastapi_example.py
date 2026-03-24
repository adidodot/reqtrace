"""
Contoh penggunaan reqtrace v0.3.0 dengan FastAPI.

Jalankan dengan:
    uvicorn examples.fastapi_example:app --reload
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from reqtrace import ReqTrace
from reqtrace.middleware import ReqTraceMiddleware


# -------------------------------------------------------------------
# Pilih salah satu konfigurasi:
# -------------------------------------------------------------------

# Mode 1: terminal + auto-diff (tanpa filter)
rt = ReqTrace(output="terminal", diff=True)

# Mode 2: blacklist — sembunyikan docs & semua 200
# rt = ReqTrace(
#     output="terminal",
#     filters=ReqTraceFilter(
#         mode="blacklist",
#         routes=["/docs", "/redoc", "/openapi.json"],
#         status_codes=[200],
#     )
# )

# Mode 3: whitelist — hanya log error
# rt = ReqTrace(
#     output="terminal",
#     filters=ReqTraceFilter(
#         mode="whitelist",
#         status_codes=["4xx", "5xx"],
#     )
# )

# Mode 4: whitelist — hanya log POST dan PUT
# rt = ReqTrace(
#     output="terminal",
#     filters=ReqTraceFilter(
#         mode="whitelist",
#         methods=["POST", "PUT", "DELETE"],
#     )
# )

# -------------------------------------------------------------------

app = FastAPI(title="reqtrace example")
app.add_middleware(ReqTraceMiddleware, config=rt.config)

_users = [
    {"id": 1, "name": "Alice", "email": "alice@example.com"},
    {"id": 2, "name": "Bob", "email": "bob@example.com"},
]


class UserCreate(BaseModel):
    name: str
    email: str


@app.get("/users")
def list_users():
    return {"status": "ok", "data": _users}


@app.get("/users/{user_id}")
def get_user(user_id: int):
    user = next((u for u in _users if u["id"] == user_id), None)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found")
    return {"status": "ok", "data": user}


@app.post("/users", status_code=201)
def create_user(payload: UserCreate):
    new_user = {"id": len(_users) + 1, **payload.model_dump()}
    _users.append(new_user)
    return {"status": "ok", "data": new_user}
