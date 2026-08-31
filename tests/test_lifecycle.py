from runner_service.lifecycle import *

class Fake:
    def __init__(self): self.deleted=[]
    def delete(self,k,n): self.deleted.append((k,n))

def test_cleanup_all_paths():
    f=Fake(); s=Submission("job-1","secret-1","code-1")
    assert cleanup_submission(f,s)==[]
    assert f.deleted == [("jobs","job-1"),("secrets","secret-1"),("configmaps","code-1")]

