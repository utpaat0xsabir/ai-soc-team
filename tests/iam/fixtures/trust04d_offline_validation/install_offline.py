from pathlib import Path
from email.parser import Parser
import sys,json,hashlib,zipfile,os
work=Path(__file__).parent;assert sys.prefix==str(work/'env')
assert not Path('/home').exists() and not Path('/run/postgresql').exists()
assert not any(line.split()[1]=='00000000' for line in Path('/proc/net/route').read_text().splitlines()[1:])
sys.path.insert(0,'/usr/share/python-wheels/pip-22.0.2-py3-none-any.whl')
from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name
from pip._vendor.packaging.markers import default_environment
lock=json.loads((work/'dependency-lock.json').read_text());pins={r['package']:r['version'] for r in lock['artifacts']};e=default_environment();e['extra']=''
for r in lock['artifacts']:
 path=work/'wheelhouse'/r['filename'];assert hashlib.sha256(path.read_bytes()).hexdigest()==r['sha256']==r['publisher_sha256']
 with zipfile.ZipFile(path) as z:
  names=[n for n in z.namelist() if n.endswith('.dist-info/METADATA')];assert len(names)==1
  meta=Parser().parsestr(z.read(names[0]).decode(),headersonly=True)
  assert canonicalize_name(meta['Name'])==r['package'] and meta['Version']==r['version']
  active=[]
  for raw in meta.get_all('Requires-Dist',[]):
   dep=Requirement(raw)
   if dep.marker is not None and not dep.marker.evaluate(e):continue
   name=canonicalize_name(dep.name);assert name in pins and dep.specifier.contains(pins[name]) and not dep.url and not dep.extras,raw
   active.append(raw)
  assert {str(Requirement(x)) for x in active}=={str(Requirement(x)) for x in r['active_dependencies']},('metadata mismatch',r['package'])
from pip._internal.cli.main import main
args=['--isolated','--disable-pip-version-check','--no-cache-dir','install','--no-index','--find-links='+str(work/'wheelhouse'),'--require-hashes','--only-binary=:all:','--no-deps','--prefix='+str(work/'env'),'-r',str(work/'requirements.lock')]
code=main(args)
assert 'cryptography' not in sys.modules
raise SystemExit(code)
