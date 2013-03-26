import immlib
from libevent import ExceptionEvent

DESC="Get a log of current debugevent"

def main(args):
    imm=immlib.Debugger()
    evento = imm.getEvent()
    if evento:
        if isinstance(evento, ExceptionEvent):
            for a in evento.Exception:
                imm.Log("Exception: %s (0x%08x)" % (a.getType(), a.ExceptionCode), focus = 1)
                imm.Log("Exception address: 0x%08x" % a.ExceptionAddress)
                imm.Log("Exception num param: %d" % a.NumberParameters)
                for value in a.ExceptionInformation:
                    imm.Log(hex(value))
        else:
            imm.Log("Last event type: 0x%08x (%s) " % (evento.dwDebugEventCode, str(evento) ) )
        return "Works"
    else:
        return "Cannot handle this exception"