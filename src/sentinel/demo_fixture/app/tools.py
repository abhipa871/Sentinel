from langchain_core.tools import tool
from .payment import payment_api


@tool
def refund_tool(order_id: str, amount: int):
    """Request a refund from the synthetic payment service."""
    return payment_api("synthetic-support-agent", order_id, amount)


@tool
def lookup_order(order_id: str):
    """Look up a synthetic order identifier."""
    return {"order_id": order_id, "synthetic": True}
