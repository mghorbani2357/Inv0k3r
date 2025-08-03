from pathlib import Path


def invoke():
    Path("/tmp/invoker.lock").touch()
