import immlib
from libevent import ExceptionEvent

DESC = "Get a log of current debugevent"
NAME = "getevent"

def usage(imm):
    imm.log("!%s" % NAME)
    imm.log("%s" % DESC)

def main(args):
    imm=immlib.Debugger()
    evento = imm.getEvent()
    if evento:
        if isinstance(evento, ExceptionEvent):
            for a in evento.Exception:
                imm.log("Exception: %s (0x%08x)" % (a.getType(), a.ExceptionCode), focus = 1)
                imm.log("Exception address: 0x%08x" % a.ExceptionAddress)
                imm.log("Exception num param: %d" % a.NumberParameters)
                for value in a.ExceptionInformation:
                    imm.log(hex(value))
        else:
            imm.log("Last event type: 0x%08x (%s) " % (evento.dwDebugEventCode, str(evento) ) )
        return "Works"
    else:
        return "Cannot handle this exception"
