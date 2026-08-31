import pytest
from runner_service.artifacts import *

def test_scoped_upload_and_retention():
    upload = issue_upload("own_"+"a"*32, "job-1", "trace.zip", now=10)
    assert upload.key == "own_"+"a"*32+"/job-1/trace.zip"
    assert upload.expires_at == 310
    assert retention_deadline(10, 60) == 70
    with pytest.raises(ValidationError): issue_upload("own_"+"a"*32, "job-1", "x", ttl=901)

