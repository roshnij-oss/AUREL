import os, tempfile
os.environ["AUREL_DB"] = os.path.join(tempfile.mkdtemp(prefix="aurel-test-"), "test.db")   # tests never touch your real history
