import base64, hashlib, hmac, json
import pytest
from runner_service.security import *

def token(claims, secret=b"test"):
    enc=lambda x: base64.urlsafe_b64encode(json.dumps(x,separators=(",", ":")).encode()).rstrip(b"=").decode()
    h,b=enc({"alg":"HS256","typ":"JWT"}),enc(claims)
    s=base64.urlsafe_b64encode(hmac.new(secret,f"{h}.{b}".encode(),hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{h}.{b}.{s}"

def test_access_jwt_and_opaque_owner():
    c=validate_access_jwt(token({"sub":"user-1","aud":"app","exp":110}),b"test","app",now=100)
    assert opaque_owner_id(c.subject,b"salt").startswith("own_")

@pytest.mark.parametrize("claims", [{"sub":"x","aud":"bad","exp":110},{"sub":"x","aud":"app","exp":99}])
def test_jwt_rejected(claims):
    with pytest.raises(ValidationError): validate_access_jwt(token(claims),b"test","app",now=100)

def test_validation_redaction_and_artifact_scope():
    p=validate_submission({"code":"await page.goto('https://example.com')","env":{"TOKEN":"secret"}})
    assert redact_secrets("TOKEN=secret", [p["env"]["TOKEN"]]) == "TOKEN=[REDACTED]"
    a=Artifact("own_"+"a"*32,"job-1",artifact_key("own_"+"a"*32,"job-1","trace.zip"),100)
    with pytest.raises(PermissionError): authorize_artifact("own_"+"b"*32,a)

def test_bounds():
    with pytest.raises(ValidationError): validate_submission({"code":"x","timeoutSeconds":901})
    with pytest.raises(ValidationError): validate_submission({"code":"x","env":{"bad-name":"x"}})

