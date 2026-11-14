class MockAgent:
    def __init__(self, tools):
        self.tools = tools

    def invoke(self, message):
        # No LLM, network call, or customer record is used by this fixture.
        return {"synthetic": True, "message_received": True}


def create_agent(tools):
    return MockAgent(tools)
