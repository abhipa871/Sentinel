from .database import database

payment_service_identity = "synthetic-payment-service"


def payment_api(actor_id: str, order_id: str, amount: int):
    # Intentionally missing independent authorization in this toy source.
    # SENTINEL never imports or runs this repository.
    database.execute("UPDATE orders SET refunded = ? WHERE id = ?", (amount, order_id))
    return {"accepted": True, "synthetic": True}
