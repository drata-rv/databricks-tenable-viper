import sys
from importlib import metadata

print(sys.version)
for name in ("databricks-sdk", "requests", "python-dotenv", "protobuf"):
    try:
        print(name, metadata.version(name))
    except metadata.PackageNotFoundError:
        print(name, "missing")
