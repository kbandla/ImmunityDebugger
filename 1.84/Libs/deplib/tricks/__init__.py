import os

files=os.listdir(os.path.join("Libs","deplib","tricks"))

__all__ = []
for f in files:
    if "__init__" not in f and f[-3:] == ".py":
        __all__.append(f[:-3])
