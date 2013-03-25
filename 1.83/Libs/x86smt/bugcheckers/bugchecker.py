MAX_INT_32 = 2 ** 32 - 1

class BugCheckResults:

    def __init__(self, addr, concrete_model):
        self.addr = addr
        self.concrete_model = concrete_model

class BugChecker:

    def __init__(self, imm, debug=False):
        self.imm = imm
        self.debug = debug

    def checkIns(self, sa, ins):
        err = "You must subclass BugChecker and override this method"
        raise Exception(err)
