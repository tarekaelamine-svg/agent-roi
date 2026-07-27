from __future__ import annotations

import base64
import builtins
import json
import time
from types import SimpleNamespace

import pytest

from agent_roi.enterprise.control_plane import HMACPolicySigner, PolicyBundle
from agent_roi.enterprise.identity import AuthenticationError, Principal
from agent_roi.enterprise.runtime import EnterpriseSentinelRunner
from agent_roi.enterprise.signers import (
    AWSKMSPolicySigner, AzureKeyVaultPolicySigner, ExternalSignerError,
    GCPKMSPolicySigner, PKCS11PolicySigner, VaultTransitPolicySigner, _unb64,
)
from agent_roi.enterprise.workload_identity import (
    AzureManagedIdentityProvider, GCPMetadataIdentityProvider,
    OAuthClientCredentialsProvider, SPIFFEIdentityVerifier,
    WorkloadIdentityPolicy, WorkloadOIDCVerifier,
)


class Response:
    def __init__(self, payload): self.payload=payload
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def read(self):
        if isinstance(self.payload,bytes): return self.payload
        return json.dumps(self.payload).encode()


def test_all_external_signer_success_and_failure_paths(monkeypatch):
    payload=b"data"; signature=b"sig"
    with pytest.raises(ExternalSignerError): _unb64("@@")
    with pytest.raises(ValueError): AWSKMSPolicySigner("",client=object())
    class AWS:
        def sign(self,**kw): return {"Signature":signature}
        def verify(self,**kw): return {"SignatureValid":True}
    aws=AWSKMSPolicySigner("key",client=AWS())
    signed=aws.sign(payload); assert aws.verify(payload,signed)
    class BadAWS:
        def sign(self,**kw): raise RuntimeError()
        def verify(self,**kw): raise RuntimeError()
    with pytest.raises(ExternalSignerError): AWSKMSPolicySigner("k",client=BadAWS()).sign(payload)
    with pytest.raises(ExternalSignerError): AWSKMSPolicySigner("k",client=BadAWS()).verify(payload,signed)

    original=builtins.__import__
    def block(name,*a,**k):
        if name=="boto3": raise ImportError()
        return original(name,*a,**k)
    monkeypatch.setattr(builtins,"__import__",block)
    with pytest.raises(RuntimeError,match="boto3"): AWSKMSPolicySigner("k")
    monkeypatch.setattr(builtins,"__import__",original)

    with pytest.raises(ValueError): AzureKeyVaultPolicySigner("",client=None)
    class Azure:
        def sign(self,a,d): return SimpleNamespace(signature=signature)
        def verify(self,a,d,s): return SimpleNamespace(is_valid=True)
    az=AzureKeyVaultPolicySigner("k",client=Azure()); azsig=az.sign(payload); assert az.verify(payload,azsig)
    class BadAzure:
        def sign(self,*a): raise RuntimeError()
        def verify(self,*a): raise RuntimeError()
    with pytest.raises(ExternalSignerError): AzureKeyVaultPolicySigner("k",client=BadAzure()).sign(payload)
    with pytest.raises(ExternalSignerError): AzureKeyVaultPolicySigner("k",client=BadAzure()).verify(payload,azsig)

    with pytest.raises(ValueError): GCPKMSPolicySigner("",client=None,verify_callback=None)
    class ObjGCP:
        def asymmetric_sign(self,request): return SimpleNamespace(signature=signature)
    gcp=GCPKMSPolicySigner("k",client=ObjGCP(),verify_callback=lambda p,s:s==signature)
    gcpsig=gcp.sign(payload); assert gcp.verify(payload,gcpsig)
    class MapGCP:
        def asymmetric_sign(self,request): return {"signature":signature}
    assert GCPKMSPolicySigner("k",client=MapGCP(),verify_callback=lambda *a:True).sign(payload)
    class BadGCP:
        def asymmetric_sign(self,request): raise RuntimeError()
    with pytest.raises(ExternalSignerError): GCPKMSPolicySigner("k",client=BadGCP(),verify_callback=lambda *a:True).sign(payload)
    with pytest.raises(ExternalSignerError): GCPKMSPolicySigner("k",client=ObjGCP(),verify_callback=lambda *a:(_ for _ in ()).throw(RuntimeError())).verify(payload,gcpsig)

    for args in (("http://vault","k","t"),("https://vault","","t"),("https://vault","k","")):
        with pytest.raises(ValueError): VaultTransitPolicySigner(args[0],args[1],token=args[2])
    vault=VaultTransitPolicySigner("https://vault","key",token="t",key_version=2)
    calls=[]
    monkeypatch.setattr(vault,"_post",lambda op,body: calls.append((op,body)) or ({"data":{"signature":"vault:v1:s"}} if op=="sign" else {"data":{"valid":True}}))
    assert vault.sign(payload)=="vault:v1:s" and vault.verify(payload,"s") and calls[0][1]["key_version"]==2
    monkeypatch.setattr("agent_roi.enterprise.signers.urlrequest.urlopen",lambda *a,**k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(ExternalSignerError): VaultTransitPolicySigner("https://v","k",token="t")._post("sign",{})

    with pytest.raises(ValueError): PKCS11PolicySigner("",sign_callback=None,verify_callback=None)
    pk=PKCS11PolicySigner("k",sign_callback=lambda p:signature,verify_callback=lambda p,s:s==signature)
    pksig=pk.sign(payload); assert pk.verify(payload,pksig)
    bad=PKCS11PolicySigner("k",sign_callback=lambda p:(_ for _ in ()).throw(RuntimeError()),verify_callback=lambda p,s:(_ for _ in ()).throw(RuntimeError()))
    with pytest.raises(ExternalSignerError): bad.sign(payload)
    with pytest.raises(ExternalSignerError): bad.verify(payload,pksig)


def test_workload_policies_oidc_and_http_token_providers(monkeypatch):
    principal=Principal(subject="svc:a",organization_id="o",attributes={"identity_type":"workload","env":"prod"})
    policy=WorkloadIdentityPolicy(allowed_subjects=("svc:*",),required_attributes={"env":"prod"})
    assert policy.validate(principal) is principal
    with pytest.raises(AuthenticationError,match="Identity type"): policy.validate(Principal("x","o",attributes={"identity_type":"human"}))
    with pytest.raises(AuthenticationError,match="allowlisted"): policy.validate(Principal("x","o",attributes={"identity_type":"workload"}))
    with pytest.raises(AuthenticationError,match="attribute mismatch"): policy.validate(Principal("svc:x","o",attributes={"identity_type":"workload","env":"dev"}))

    class V:
        def verify(self,token): return Principal("svc:x","o",attributes={"client_id":"client"})
    verifier=WorkloadOIDCVerifier(V(),policy=WorkloadIdentityPolicy(allowed_subjects=("svc:*",)))
    assert verifier.verify("t").attributes["identity_type"]=="workload"
    assert verifier.verify_authorization_header("Bearer token").subject=="svc:x"
    with pytest.raises(AuthenticationError): verifier.verify_authorization_header("Basic x")

    with pytest.raises(ValueError): OAuthClientCredentialsProvider("http://x","a","b")
    with pytest.raises(ValueError): OAuthClientCredentialsProvider("https://x","","b")
    responses=[Response({"access_token":"tok","expires_in":300})]
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: responses.pop(0))
    oauth=OAuthClientCredentialsProvider("https://x","id","secret",scope="s",audience="a",extra_fields={"x":"y"},refresh_skew_seconds=0)
    assert oauth.token()=="tok" and oauth.token()=="tok"
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: Response({}))
    with pytest.raises(AuthenticationError,match="no access_token"): OAuthClientCredentialsProvider("https://x","i","s").token()
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(AuthenticationError,match="token request failed"): OAuthClientCredentialsProvider("https://x","i","s").token()

    with pytest.raises(ValueError): AzureManagedIdentityProvider("")
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: Response({"access_token":"az"}))
    assert AzureManagedIdentityProvider("resource",client_id="id").token()=="az"
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: Response({}))
    with pytest.raises(AuthenticationError,match="no access_token"): AzureManagedIdentityProvider("r").token()
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(AuthenticationError,match="request failed"): AzureManagedIdentityProvider("r").token()

    with pytest.raises(ValueError): GCPMetadataIdentityProvider("")
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: Response(b"gcp"))
    assert GCPMetadataIdentityProvider("aud").token()=="gcp"
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: Response(b""))
    with pytest.raises(AuthenticationError,match="no token"): GCPMetadataIdentityProvider("aud").token()
    monkeypatch.setattr("agent_roi.enterprise.workload_identity.urlrequest.urlopen",lambda *a,**k: (_ for _ in ()).throw(OSError()))
    with pytest.raises(AuthenticationError,match="request failed"): GCPMetadataIdentityProvider("aud").token()

    with pytest.raises(ValueError): SPIFFEIdentityVerifier(trust_domain="",organization_id="o")
    spiffe=SPIFFEIdentityVerifier(trust_domain="Example.ORG",organization_id="o",allowed_paths=("/agent/*",),roles=("r",))
    assert spiffe.verify("spiffe://example.org/agent/a").roles==frozenset({"r"})
    with pytest.raises(AuthenticationError,match="trust domain"): spiffe.verify("spiffe://bad/agent/a")
    with pytest.raises(AuthenticationError,match="path"): spiffe.verify("spiffe://example.org/other")


def bundle():
    return PolicyBundle.create(organization_id="o",name="p",environment="prod",version="2",policy={"guardrails":{"max_steps":2,"max_tool_calls":2,"max_cost_usd":1,"allowed_tools":[]},"decision_policy":{"min_confidence":.5,"abstain_action":"human_review"}},signer=HMACPolicySigner(b"x"*32),created_by="u")


class CP:
    def __init__(self,fail=False,for_agent=True): self.calls=[]; self.fail=fail; self.for_agent=for_agent
    def get_policy_for_agent(self,*args):
        if not self.for_agent: raise AttributeError
        return bundle()
    def get_active_policy(self,*args): return bundle()
    def heartbeat(self,**kwargs):
        self.calls.append(kwargs)
        if self.fail: raise RuntimeError("hb")


def test_enterprise_runner_policy_resolution_heartbeat_and_failures(monkeypatch):
    cp=CP(); runner=EnterpriseSentinelRunner.from_control_plane(control_plane_client=cp,organization_id="o",environment="prod",agent_id="a",policy_name="p")
    assert runner.run(lambda c,p:"ok",None).output=="ok"
    assert [c["status"] for c in cp.calls]==["running","production"]
    # fallback when method is absent
    cp2=SimpleNamespace(get_active_policy=lambda *a:bundle(),heartbeat=lambda **k:None)
    assert EnterpriseSentinelRunner.from_control_plane(control_plane_client=cp2,organization_id="o",environment="prod",agent_id="a",policy_name="p").policy_bundle.version=="2"
    failing=CP(fail=True); r=EnterpriseSentinelRunner(control_plane_client=failing,policy_bundle=bundle(),organization_id="o",environment="prod",agent_id="a")
    r.heartbeat("x"); assert r.heartbeat_errors
    with pytest.raises(RuntimeError): EnterpriseSentinelRunner(control_plane_client=failing,policy_bundle=bundle(),organization_id="o",environment="prod",agent_id="a",heartbeat_fail_closed=True).heartbeat("x")
    cp3=CP(); r=EnterpriseSentinelRunner(control_plane_client=cp3,policy_bundle=bundle(),organization_id="o",environment="prod",agent_id="a")
    with pytest.raises(ValueError): r.run(lambda c,p:(_ for _ in ()).throw(ValueError()),None)
    assert cp3.calls[-1]["status"]=="error"


@pytest.mark.asyncio
async def test_enterprise_runner_async_success_and_error():
    cp=CP(); r=EnterpriseSentinelRunner(control_plane_client=cp,policy_bundle=bundle(),organization_id="o",environment="prod",agent_id="a")
    async def ok(c,p): return "ok"
    assert (await r.arun(ok,None)).output=="ok"
    async def bad(c,p): raise ValueError()
    with pytest.raises(ValueError): await r.arun(bad,None)
    assert cp.calls[-1]["status"]=="error"
