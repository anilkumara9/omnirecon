from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer

app = FastAPI()
security = HTTPBearer()

class ItemStore:
    def __init__(self):
        self.items = {}

    def add(self, item):
        self.items[item["id"]] = item

@app.get("/items")
def list_items():
    return []

@app.post("/items", status_code=201)
def create_item(payload: dict):
    return payload

@app.get("/items/{item_id}")
def get_item(item_id: int, creds=Depends(security)):
    return {"id": item_id}
