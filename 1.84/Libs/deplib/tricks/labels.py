"""
Used to define labels where you can jump to, it doesnt specify a new command per se.

"""

def init(instance):
    instance.register_operation("label", analyzer)

def analyzer(c_instance, name):
    currentCmd = len(c_instance.cmdList)
    c_instance.labels[name]=currentCmd
    
    return None #do not add a command for this
