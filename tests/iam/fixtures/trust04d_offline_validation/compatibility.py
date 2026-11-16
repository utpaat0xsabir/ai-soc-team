from pathlib import Path
import json,sys,platform,collections
from importlib.metadata import version
w=Path(__file__).parent
assert sys.prefix==str(w/'env') and not Path('/home').exists()
assert not Path('/proc/net/route').read_text().splitlines()[1:]
import cryptography
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.backends.openssl.backend import backend
assert str(cryptography.__file__).startswith(str(w/'env'))
r={'classification':'PUBLIC_NON_SECRET_TEST_ONLY','python':platform.python_version(),'dependencies':{x:version(x) for x in ['cryptography','cffi','pycparser','typing-extensions']},'openssl':backend.openssl_version_text(),'isolation':{'home_visible':False,'network_routes':[]},'rfc':[],'wycheproof':[],'stop':None}
def verify(pk,msg,sig):
 try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(bytes.fromhex(sig),bytes.fromhex(msg));return 'ACCEPT',None
 except Exception as e:return 'REJECT',type(e).__name__
def save(): (w/'results.json').write_text(json.dumps(r,indent=2)+'\n')
a=json.loads((w/'public_vectors/rfc8032-section7_1-verification-only.json').read_text())
rows=a if isinstance(a,list) else a.get('records',[])
assert len(rows)==3
for t in rows:
 actual,exc=verify(t['public_key_hex'],t['message_hex'],t['signature_hex']);r['rfc'].append({'id':t['vector_id'],'actual':actual,'exception':exc,'expected':'ACCEPT'})
 if actual!='ACCEPT':r['stop']='RFC known-answer failure';save();raise SystemExit(2)
x=json.loads((w/'public_vectors/wycheproof-ed25519-a3d5d142.json').read_text())
allrows=sorted([(t,g['publicKey']['pk']) for g in x['testGroups'] for t in g['tests']],key=lambda z:z[0]['tcId'])
assert len(allrows)==210
r['original_verdict_counts']=dict(collections.Counter(t['result'] for t,p in allrows))
for t,pk in allrows:
 actual,exc=verify(pk,t['msg'],t['sig']);strict=bool(set(t['flags']) & {'SmallOrderPublicKey','MixedOrderPublicKey'})
 expected='REJECT' if strict or t['result']=='invalid' else ('ACCEPT' if t['result']=='valid' else 'REVIEW_REQUIRED')
 row={'tcId':t['tcId'],'original_verdict':t['result'],'flags':t['flags'],'comment':t['comment'],'public_key_hex':pk,'message_hex':t['msg'],'signature_hex':t['sig'],'actual':actual,'exception':exc,'profile_expectation':expected,'classification':'REQUIRES_REVIEW' if expected=='REVIEW_REQUIRED' else ('PROFILE_COMPATIBLE' if (actual==expected) else 'PROFILE_INCOMPATIBLE')}
 r['wycheproof'].append(row)
 if expected in ('ACCEPT','REJECT') and actual!=expected:
  r['stop']={'reason':'Frozen profile incompatibility','tcId':t['tcId'],'basis':'Frozen profile rejects small/mixed-order public keys' if strict else 'Published valid/invalid verdict mismatch'};break
r['not_run_wycheproof']=210-len(r['wycheproof']);save()
print(json.dumps({'rfc_count':len(r['rfc']),'wycheproof_run':len(r['wycheproof']),'stop':r['stop'],'openssl':r['openssl']}))
