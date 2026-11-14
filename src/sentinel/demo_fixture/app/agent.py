from .agent_runtime import create_agent
from .tools import refund_tool, lookup_order

refund_tool_scopes = ["refund:request"]
support_agent = create_agent(tools=[refund_tool])
