class MockDatabase:
    def execute(self, statement, parameters):
        return {"synthetic": True}


database = MockDatabase()
