from fastapi import FastAPI
from pydantic import BaseModel
from network import NetworkCore

app = FastAPI()
net = NetworkCore()

class LoginReq(BaseModel):
    app_id: str
    password: str

@app.post("/login")
def login(req: LoginReq):
    ok = net.login(req.app_id, req.password)
    return {"success": ok}

@app.get("/scan")
def scan():
    devices = net.scan()
    return {"raw": devices}
