from fastapi import FastAPI
from .agent import support_agent

app = FastAPI()


@app.post("/support")
def support_message(message: str):
    return support_agent.invoke(message)
