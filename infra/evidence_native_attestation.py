"""Fixed PUBLIC same-image probes; no issuer, proof key or private eligibility.

Confinement probes never read stdin. The strict C harness runs trusted public
vectors BEFORE helper confinement, under the checked outer container controls.
"""
from __future__ import annotations

import base64
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
import uuid
import zlib

from infra import evidence_container as base
from infra import evidence_container_native as public
from infra import evidence_native_runtime as runtime
from infra import evidence_native_ownership as ownership_journal
from infra.native import pcre_probe, strict_probe
from backend.apps.operations import evidence_scan_protocol as protocol

ROOT = Path(__file__).resolve().parents[1]
STRICT = ROOT / 'infra/native/strict_probe.py'
PCRE = ROOT / 'infra/native/pcre_probe.py'
PINS = ((Path(public.__file__), '86573ad4bbe9078b47a805786fa2aaeaec003abbe734b87ad6bfd72e63c02c15'),
        (Path(runtime.__file__), '69af8b1564726ddde37ea8aa49ebf86a4419118b474e1bbd9098279568775c82'),
        (public.HELPER, 'de930340e056f64157e4ab82e6a528a2ff362477278a5e711d815606e96de0bb'),
        (STRICT, '021d12e778a40bb2f6e3820ec2055d0a4149882a3a2b0438924dcecf38a1c078'),
        (Path(base.__file__), '921f26e53ea67ebb066d534f682cef7fed215c708fed9426b14231e1b1043628'),
        (Path(ownership_journal.__file__), '6544725a99a0d9941db347ea3c81b8d3e8ea8f58ae88886289c320ee6f2ef4d1'),
        (PCRE, ownership_journal.PCRE_PROBE))
OWNER = 'kapit-same-image-public-probe-v1'
SCENARIOS = frozenset({'confinement','storage','x32','preopened_fd','shm_namespace'})
CASES = (
    ('png_positive','COMPLETION','CLEAN'),('jpeg_positive','COMPLETION','CLEAN'),
    ('eicar_png','DETECTION','NOT_CLEAN'),('png_zero_width','PARSER','NONCLEAN'),
    ('png_truncated_chunk','PARSER','NONCLEAN'),('jpeg_before_sos','PARSER','NONCLEAN'),
    ('jpeg_jpg7','PARSER','NONCLEAN'),('raw_no_image','COMPLETION','NONCLEAN'),
    ('fmap_null','PRECONDITION','NONCLEAN'),('fmap_short','PRECONDITION','NONCLEAN'),
    ('fmap_overlimit','PRECONDITION','NONCLEAN'),('options_parse_off','PRECONDITION','NONCLEAN'),
    ('engine_max_file','ENGINE_LIMIT','NONCLEAN'),('engine_max_scan','ENGINE_LIMIT','NONCLEAN'))


class ProbeUnavailable(RuntimeError):
    def __init__(self, code='CANDIDATE_PROBE_UNAVAILABLE'):
        self.code = code if code in {'CANDIDATE_PROBE_UNAVAILABLE','CANDIDATE_CLEANUP_UNCONFIRMED'} else 'CANDIDATE_PROBE_UNAVAILABLE'
        super().__init__(self.code)


def require(value, code='CANDIDATE_PROBE_UNAVAILABLE'):
    if value is not True: raise ProbeUnavailable(code)


def _pins():
    for path, expected in PINS:
        raw=path.read_bytes()
        require(len(raw)<=262144 and hashlib.sha256(raw).hexdigest()==expected)


def _strict_program():
    _pins();raw=STRICT.read_bytes();encoded=base64.b64encode(raw).decode('ascii')
    return ("import base64,hashlib\nraw=base64.b64decode('"+encoded+"')\n"
        "assert hashlib.sha256(raw).hexdigest()=='"+PINS[3][1]+"'\n"
        "exec(compile(raw,'<fixed-public-strict>','exec'),{'__name__':'__main__'})\n")


def _pcre_program():
    """One trusted fixed-source transport; no caller bytes or decompression API."""
    _pins();raw=PCRE.read_bytes()
    require(0<len(raw)<=262144 and hashlib.sha256(raw).hexdigest()==ownership_journal.PCRE_PROBE)
    packed=zlib.compress(raw,9);require(0<len(packed)<=65536)
    encoded=base64.b64encode(packed).decode('ascii')
    return ("import base64,hashlib,zlib\npacked=base64.b64decode('"+encoded+"',validate=True)\n"
        "assert len(packed)=="+str(len(packed))+"\nd=zlib.decompressobj()\nraw=d.decompress(packed,"+str(len(raw)+1)+")\n"
        "assert len(raw)=="+str(len(raw))+" and d.eof and not d.unused_data and not d.unconsumed_tail\n"
        "assert hashlib.sha256(raw).hexdigest()=='"+ownership_journal.PCRE_PROBE+"'\n"
        "exec(compile(raw,'<fixed-public-pcre>','exec'),{'__name__':'__main__'})\n")


@dataclass(frozen=True)
class _Probe:
    phase: runtime._Phase
    scenario: str

    @property
    def name(self): return 'kapit-same-image-public-'+self.phase.token

    @property
    def labels(self):
        return self.phase.labels | {'org.kapit.owner':OWNER,'org.kapit.purpose':'same-image-public-only',
            'org.kapit.scenario':self.scenario,'org.kapit.probe':PINS[3][1] if self.scenario=='strict' else ownership_journal.PCRE_PROBE if self.scenario=='pcre' else PINS[0][1]}

    @property
    def command(self):
        if self.scenario=='pcre':return ['-I','-B','-c',_pcre_program()]
        return ['-I','-B','-c',_strict_program()] if self.scenario=='strict' else ['-I','-B','-c',public.probe_program(),self.scenario]


def create_args(probe, *, profile_path):
    require(type(probe) is _Probe and probe.scenario in SCENARIOS|{'strict','pcre'} and
            (probe.scenario not in ('strict','pcre') or probe.phase.binding.mode=='scan'))
    source=runtime.create_args(probe.phase,profile_path=profile_path)
    require(source[-7:]==[probe.phase.candidate.image_id,*probe.phase.command])
    prefix=[];index=0
    while index<len(source)-7:
        if source[index]=='--label':index+=2;continue
        if source[index]=='--name':prefix.extend(['--name',probe.name]);index+=2;continue
        prefix.append(source[index]);index+=1
    for key,value in sorted(probe.labels.items()):prefix.extend(['--label',key+'='+value])
    result=prefix+[probe.phase.candidate.image_id,*probe.command]
    require(len(subprocess.list2cmdline(result))<30000)
    return result


def verify_inspection(value, probe, *, container_id):
    require(type(value) is dict and value.get('Id')==container_id and value.get('Name')=='/'+probe.name
            and value.get('Image')==probe.phase.candidate.image_id)
    config=value.get('Config');require(type(config) is dict and config.get('Labels')==probe.labels and config.get('Cmd')==probe.command)
    require(public._environment(config.get('Env'))==runtime.EFFECTIVE_ENV)
    normalized=deepcopy(value)
    normalized['Name']='/'+probe.phase.name
    normalized['Config'].update(Labels=probe.phase.labels,Cmd=probe.phase.command)
    try:runtime.verify_inspection(normalized,probe.phase,container_id=container_id)
    except Exception:raise ProbeUnavailable() from None


def _attach(argv, *, timeout):
    """Empty anonymous stdin held; independent output limits; exact CLI reap."""
    process=None;threads=[];stdout=bytearray();failed=threading.Event()
    deadline=time.monotonic()+timeout
    def read(pipe,maximum,save):
        try:
            count=0
            while True:
                block=os.read(pipe.fileno(),4096)
                if not block:break
                count+=len(block);require(count<=maximum)
                if save:stdout.extend(block)
        except BaseException:failed.set()
    try:
        process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            bufsize=0,close_fds=True,shell=False,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),
            env={k:v for k,v in os.environ.items() if k.upper() in {'SYSTEMROOT','WINDIR','TEMP','TMP'}})
        for pipe,maximum,save in ((process.stdout,65536,True),(process.stderr,16384,False)):
            thread=threading.Thread(target=read,args=(pipe,maximum,save),daemon=True);threads.append(thread);thread.start()
        while process.poll() is None:
            require(not failed.is_set() and time.monotonic()<deadline);time.sleep(.01)
        code=process.wait(timeout=5)
        require(type(code) is int and time.monotonic()<deadline and not failed.is_set())
    except ProbeUnavailable:raise
    except Exception:raise ProbeUnavailable() from None
    finally:
        if process is not None:
            stopped,joined=False,True
            try:
                if process.poll() is None:process.kill()
                exit_code=process.wait(timeout=5);stopped=type(exit_code) is int and process.poll() is not None
            except BaseException:pass
            for thread in threads:
                if thread.ident is not None:
                    try:thread.join(timeout=5);joined=joined and not thread.is_alive()
                    except BaseException:joined=False
            if stopped and joined:
                for pipe in (process.stdin,process.stdout,process.stderr):
                    try:pipe.close()
                    except BaseException:joined=False
            require(stopped and joined,'CANDIDATE_CLEANUP_UNCONFIRMED')
    require(not failed.is_set())  # Covers late stderr failure observed at join.
    return code,bytes(stdout)


def _strict_payload(raw):
    def pairs(items):
        value={}
        for key,item in items:require(key not in value);value[key]=item
        return value
    try:
        require(type(raw) is bytes and 0<len(raw)<=65536)
        value=json.loads(raw.decode('utf-8',errors='strict'),object_pairs_hook=pairs,parse_constant=lambda _:require(False))
        require(type(value) is dict and set(value)=={'schema','scope','completed','passed','cases','native_eligible'}
            and type(value['schema']) is int and value['schema']==1 and value['scope']=='PUBLIC_STRICT_NATIVE_PROBE_ONLY'
            and type(value['completed']) is bool and type(value['passed']) is bool and value['native_eligible'] is False
            and type(value['cases']) is list and len(value['cases'])<=len(CASES))
        for row,(name,kind,expected) in zip(value['cases'],CASES):
            require(type(row) is dict and set(row)=={'case','kind','strict','upstream','passed','normalization_observed'}
                and row['case']==name and row['kind']==kind and type(row['strict']) is str and row['strict'] in {'CLEAN','NOT_CLEAN','ERROR'}
                and type(row['upstream']) is str and row['upstream'] in {'CLEAN','NOT_CLEAN','ERROR','NOT_RUN'}
                and type(row['passed']) is bool and type(row['normalization_observed']) is bool)
            require((row['upstream']=='NOT_RUN')==(kind=='PRECONDITION'))
            passed=row['strict']!='CLEAN' if expected=='NONCLEAN' else row['strict']==expected
            require(row['passed'] is passed and row['normalization_observed'] is (row['strict']!='CLEAN' and row['upstream']=='CLEAN'))
        require(not value['completed'] or len(value['cases'])==len(CASES))
        require(value['passed'] is (value['completed'] and all(row['passed'] for row in value['cases'])))
        return value
    except Exception:raise ProbeUnavailable() from None


def _run(candidate,scenario,resource_mode,*,docker_path,profile_path):
    require(type(candidate) is runtime.Candidate and os.name=='nt' and scenario in SCENARIOS|{'strict','pcre'}
            and resource_mode in ('scan','decode') and (scenario not in ('strict','pcre') or resource_mode=='scan'))
    _pins();docker_path,profile_path=Path(docker_path),Path(profile_path)
    require(docker_path.is_absolute() and profile_path.is_absolute())
    binding=protocol.Binding(resource_mode,secrets.token_hex(32),runtime.POLICY_SHA256,candidate.signature_generation)
    probe=_Probe(runtime._Phase(candidate,binding,uuid.uuid4().hex),scenario)
    original_id=None;created=False;cli_uncertain=False;diagnostic=None;failure_summary=None
    def call(*args,timeout=15):
        nonlocal cli_uncertain
        try:
            argv=[str(docker_path),'--host',base.ENDPOINT,*args]
            require(len(subprocess.list2cmdline(argv))<30000)
            return base._bounded_command(argv,timeout=timeout,maximum=1048576)
        except base.ContainerUnavailable as error:
            if error.code=='CONTAINER_CLEANUP_UNCONFIRMED':
                cli_uncertain=True;raise ProbeUnavailable('CANDIDATE_CLEANUP_UNCONFIRMED') from None
            raise ProbeUnavailable() from None
        except Exception:raise ProbeUnavailable() from None
    def document(*args):
        code,out,_,reason=call(*args);require(type(code) is int and code==0 and reason=='EXIT')
        try:value=json.loads(out.decode('utf-8',errors='strict'))
        except Exception:raise ProbeUnavailable() from None
        require(type(value) is list and len(value)==1 and type(value[0]) is dict);return value[0]
    def ownership(value):
        require(value.get('Id')==original_id and value.get('Name')=='/'+probe.name and value.get('Image')==candidate.image_id
                and value.get('Config',{}).get('Labels')==probe.labels)
    def cgroup_v2():
        try:runtime._require_cgroup_v2(call)
        except runtime.NativeUnavailable:raise ProbeUnavailable() from None
    from contextlib import ExitStack
    from infra.evidence_tools import Windows
    api=Windows()
    with ExitStack() as stack:
        for path in (docker_path,profile_path):stack.enter_context(api.pin(path))
        for path,_ in PINS:stack.enter_context(api.pin(path,private=False))
        _pins();require(profile_path.read_bytes()==base.canonical(public.startup_profile()))
        cgroup_v2()
        image=document('image','inspect',candidate.image_id)
        try:runtime.verify_image(image,candidate)
        except Exception:raise ProbeUnavailable() from None
        code,out,_,reason=call('container','ls','--all','--no-trunc','--filter','name=^/'+probe.name+'$','--format','{{.ID}}')
        require(type(code) is int and code==0 and reason=='EXIT' and not out.strip())
        try:
            journal=stack.enter_context(ownership_journal.reserve(token=probe.phase.token,image_id=candidate.image_id,
                signature_generation=candidate.signature_generation,purpose='same-image-probe',mode=resource_mode,
                scenario=scenario,phase='probe',source_policy=runtime.POLICY_SHA256,expected_labels=probe.labels))
        except BaseException:raise ProbeUnavailable('CANDIDATE_CLEANUP_UNCONFIRMED') from None
        journal_uncertain=False
        try:
            try:journal.mark_create_attempted()
            except BaseException:journal_uncertain=True;raise ProbeUnavailable('CANDIDATE_CLEANUP_UNCONFIRMED') from None
            created=True
            code,out,_,reason=call(*create_args(probe,profile_path=profile_path))
            original_id=runtime._original_create_id(out)
            if original_id is not None:
                try:journal.record_original(original_id)
                except BaseException:journal_uncertain=True;raise ProbeUnavailable('CANDIDATE_CLEANUP_UNCONFIRMED') from None
            require(type(code) is int and code==0 and reason=='EXIT' and original_id is not None)
            cgroup_v2()
            before=document('container','inspect',original_id);verify_inspection(before,probe,container_id=original_id)
            cgroup_v2()
            cli_exit,raw=_attach([str(docker_path),'--host',base.ENDPOINT,'container','start','--attach','--interactive',original_id],
                                 timeout=runtime.LIMITS[resource_mode][2])
            cgroup_v2()
            after=document('container','inspect',original_id);verify_inspection(after,probe,container_id=original_id)
            state=after['State'];require(state.get('OOMKilled') is False and type(state.get('Pid')) is int and state['Pid']==0
                and type(state.get('ExitCode')) is int and type(cli_exit) is int and cli_exit==state['ExitCode'])
            if scenario in ('strict','pcre'):
                try:
                    payload=_strict_payload(raw) if scenario=='strict' else pcre_probe.parse_success(raw)
                    require(payload['passed'] is True and payload['completed'] is True)
                except Exception:
                    # A failure frame is diagnostic evidence only, even on exit 0.
                    # Its fixed parser validates every partial row before omitting
                    # rows and retaining only the closed location/count summary.
                    try:
                        parser=strict_probe.parse_failure if scenario=='strict' else pcre_probe.parse_failure
                        diagnostic=parser(raw)
                    except Exception:raise ProbeUnavailable() from None
                    raise ProbeUnavailable() from None
                # A success frame on a failing CLI is a generic refusal. Never
                # reinterpret its passing rows as a failure diagnostic.
                require(cli_exit==0)
            else:
                diagnostic=public._failure_frame(raw,scenario) or public._failed_check_frame(raw,scenario)
                require(cli_exit==(159 if scenario=='x32' else 0))
                try:payload=public._payload(raw,scenario)
                except Exception:raise ProbeUnavailable() from None
        except ProbeUnavailable as error:
            if diagnostic is not None:
                failure_summary={'result':diagnostic,'cleanup':'UNCONFIRMED','private_input_allowed':False}
                error.diagnostic=failure_summary
            raise
        finally:
            status='NOT_CREATED';cleanup_uncertain=False
            try:
                if created:
                    if original_id is None:
                        code,out,_,reason=call('container','ls','--all','--no-trunc','--filter','name=^/'+probe.name+'$','--format','{{.ID}}')
                        require(type(code) is int and code==0 and reason=='EXIT' and not out.strip())
                        status='CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED'
                    else:
                        # Record failure allows ONLY guarded original-ID cleanup,
                        # never normal configuration inspection/start or input.
                        value=document('container','inspect',original_id);ownership(value)
                        if value['State'].get('Running'):call('container','kill','--signal','KILL',original_id)
                        value=document('container','inspect',original_id);ownership(value)
                        require(value['State'].get('Running') is False and value['State'].get('Restarting') is False
                            and type(value['State'].get('Pid')) is int and value['State']['Pid']==0)
                        code,_,_,reason=call('container','rm',original_id);require(type(code) is int and code==0 and reason=='EXIT')
                        code,out,_,reason=call('container','ls','--all','--no-trunc','--filter','id='+original_id,'--format','{{.ID}}')
                        require(type(code) is int and code==0 and reason=='EXIT' and not out.strip())
                        status='ORIGINAL_ID_ABSENT_VERIFIED'
                require(not cli_uncertain and not journal_uncertain)
            except BaseException:cleanup_uncertain=True
            try:journal.finish('CLEANUP_UNCONFIRMED' if cleanup_uncertain else status)
            except BaseException:cleanup_uncertain=True
            if cleanup_uncertain:
                error=ProbeUnavailable('CANDIDATE_CLEANUP_UNCONFIRMED')
                if failure_summary is not None:
                    failure_summary['cleanup']='UNCONFIRMED';error.diagnostic=failure_summary
                raise error from None
            if failure_summary is not None:failure_summary['cleanup']='OWNED_CONTAINER_ABSENT_VERIFIED'
        _pins();require(profile_path.read_bytes()==base.canonical(public.startup_profile()))
    return {'schema':1,'scope':'SAME_CANDIDATE_PUBLIC_PROBE_ONLY','scenario':scenario,'resource_mode':resource_mode,
        'candidate_image_id':candidate.image_id,'declared_signature_generation':candidate.signature_generation,
        'result':payload,'cleanup':'OWNED_CONTAINER_ABSENT_VERIFIED','strict_helper_confinement':False if scenario in ('strict','pcre') else scenario!='preopened_fd',
        'private_input_allowed':False,'native_eligible':False}


def run_public_probe(candidate,scenario,*,resource_mode='scan',docker_path,profile_path):
    require(type(scenario) is str and scenario in SCENARIOS and type(resource_mode) is str)
    return _run(candidate,scenario,resource_mode,docker_path=docker_path,profile_path=profile_path)


def run_strict_probe(candidate,*,docker_path,profile_path):
    return _run(candidate,'strict','scan',docker_path=docker_path,profile_path=profile_path)


def run_pcre_probe(candidate,*,docker_path,profile_path):
    return _run(candidate,'pcre','scan',docker_path=docker_path,profile_path=profile_path)
