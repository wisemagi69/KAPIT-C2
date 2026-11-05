"""Durable ownership metadata for fixed PUBLIC native runs, never native proof.

Import does not touch files/ACLs or launch Docker. Only reserve performs host
operations, under a fresh child of the existing protected scanner build stage.
No journal reader/adoption/execution, private payload or active pointer API.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).parents[1]
STAGE = ROOT/'.cache/m1-runtime/private-scanner-build'
TOKEN = re.compile(r'[0-9a-f]{32}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
POLICY = '1e2b71ab05a6905a3c9edfe056cf83ddb4df0170560f1f04a0e7978741358105'
PUBLIC_PROBE = '86573ad4bbe9078b47a805786fa2aaeaec003abbe734b87ad6bfd72e63c02c15'
STRICT_PROBE = '021d12e778a40bb2f6e3820ec2055d0a4149882a3a2b0438924dcecf38a1c078'
PCRE_PROBE = '35b3d79b975cca07b10b6c27e770b47f3dd7178f89de35568c53f5ce57fb3a50'
FIXTURES = frozenset({'png_clean','png_metadata','jpeg_clean','jpeg_metadata','png_malformed','png_eicar'})
PROBES = frozenset({'confinement','storage','x32','preopened_fd','shm_namespace','strict','pcre'})
STATUSES = frozenset({'NOT_CREATED','CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED',
                      'ORIGINAL_ID_ABSENT_VERIFIED','CLEANUP_UNCONFIRMED'})


class OwnershipUnavailable(RuntimeError):
    def __init__(self, *, cleanup=False):
        self.code = 'OWNERSHIP_CLEANUP_UNCONFIRMED' if cleanup else 'OWNERSHIP_JOURNAL_UNAVAILABLE'
        super().__init__(self.code)


def _require(condition):
    if condition is not True: raise OwnershipUnavailable()


def _canonical(value):
    raw = json.dumps(value, sort_keys=True, separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
    _require(len(raw) <= 8192)
    return raw


def _metadata(*,token,image_id,signature_generation,purpose,mode,scenario,phase,source_policy,expected_labels):
    _require(type(token) is str and TOKEN.fullmatch(token) is not None)
    _require(type(image_id) is str and image_id.startswith('sha256:') and HASH.fullmatch(image_id[7:]) is not None and image_id[7:] != '0'*64)
    _require(type(signature_generation) is str and HASH.fullmatch(signature_generation) is not None and signature_generation != '0'*64)
    _require(type(mode) is str and mode in ('scan','decode') and type(source_policy) is str and source_policy == POLICY)
    _require(type(purpose) is str and type(scenario) is str and type(phase) is str)
    if purpose == 'native-fixture':
        _require(scenario in FIXTURES and phase in ('original_scan','decode','derivative_scan'))
        _require(mode == ('decode' if phase == 'decode' else 'scan'))
        owner,purpose_label = 'kapit-public-native-fixture-v1','public-native-fixtures-only'
        name = 'kapit-native-public-'+token
    else:
        _require(purpose == 'same-image-probe' and scenario in PROBES and phase == 'probe')
        _require(scenario not in ('strict','pcre') or mode == 'scan')
        owner,purpose_label = 'kapit-same-image-public-probe-v1','same-image-public-only'
        name = 'kapit-same-image-public-'+token
    labels = {'org.kapit.owner':owner,'org.kapit.run':token,'org.kapit.reservation':token,
              'org.kapit.purpose':purpose_label,'org.kapit.mode':mode,'org.kapit.policy':POLICY}
    if purpose == 'same-image-probe':
        labels.update({'org.kapit.scenario':scenario,'org.kapit.probe':STRICT_PROBE if scenario == 'strict' else PCRE_PROBE if scenario == 'pcre' else PUBLIC_PROBE})
    _require(type(expected_labels) is dict and expected_labels == labels and
             all(type(key) is str and type(value) is str for key,value in expected_labels.items()))
    result = {'schema':1,'token':token,'image_id':image_id,'signature_generation':signature_generation,
              'purpose':purpose,'mode':mode,'scenario':scenario,'phase':phase,'source_policy':POLICY,
              'expected_name':name,'expected_labels':dict(labels),'native_eligible':False}
    _canonical(result)
    return result


class _Host:
    """Explicit Windows operation only. Tests replace this entire boundary."""
    def __init__(self, token):
        self.token = token; self.stack = ExitStack()

    def __enter__(self):
        from infra.evidence_tools import Windows, checked
        from infra.live_recovery_drill import PrivateDirectory
        try:
            _require(os.name == 'nt')
            self.api,self.private = Windows(),PrivateDirectory()
            path = ROOT
            for part in ('',*STAGE.relative_to(ROOT).parts):
                if part: path /= part
                self.stack.enter_context(self.api.pin(checked(path),directory=True))
            # Existing parent must already satisfy the protected owner/SY/BA
            # directory policy. Never create, repair or silently adopt it.
            self.stack.enter_context(self.private.pin(STAGE,private=True,directory=True))
            self.path = checked(STAGE/('native-run-'+self.token))
            self.private.create(self.path)  # Atomic CreateDirectoryW; exists fails.
            self.stack.enter_context(self.private.pin(self.path,private=True,directory=True))
            return self
        except BaseException:
            try: self.stack.close()
            except BaseException: raise OwnershipUnavailable(cleanup=True) from None
            raise

    def save(self,name,document):
        _require(name in ('reservation.json','create-attempt.json','ownership.json','result.json'))
        raw = _canonical(document); path = self.path/name
        # Empty exclusive creation inherits the verified private child ACL.
        # Apply/verify the stricter file ACL before writing any content.
        with path.open('xb'): pass
        self.api.protect(path)
        with path.open('r+b') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        pinned = self.stack.enter_context(self.api.pin(path,private=True))
        _require(pinned.read(8193) == raw)

    def close(self):
        # ExitStack attempts every callback even if an earlier release raises.
        self.stack.close()


class _Journal:
    def __init__(self, host, metadata):
        self.host,self.metadata = host,metadata
        self.attempted = False; self.record_attempted = False; self.recorded = False
        self.original_id = None; self.failed = False; self.closed = False

    def _save(self,name,value):
        try: self.host.save(name,value)
        except BaseException:
            self.failed = True
            raise OwnershipUnavailable() from None

    def mark_create_attempted(self):
        if self.closed or self.failed or self.attempted:
            self.failed = True; raise OwnershipUnavailable()
        self._save('create-attempt.json',{'schema':1,'token':self.metadata['token'],'create_attempted':True,'native_eligible':False})
        self.attempted = True

    def record_original(self,container_id):
        if (self.closed or self.failed or not self.attempted or self.record_attempted or
                type(container_id) is not str or HASH.fullmatch(container_id) is None or container_id == '0'*64):
            self.failed = True; raise OwnershipUnavailable()
        self.record_attempted = True; self.original_id = container_id
        self._save('ownership.json',dict(self.metadata,original_id=container_id))
        self.recorded = True

    def finish(self,status):
        uncertain = self.closed or self.failed or type(status) is not str or status not in STATUSES
        if not uncertain:
            uncertain = ((status == 'NOT_CREATED' and self.attempted) or
                         (status == 'CREATE_ID_UNAVAILABLE_ABSENCE_VERIFIED' and (not self.attempted or self.record_attempted)) or
                         (status == 'ORIGINAL_ID_ABSENT_VERIFIED' and not self.recorded))
        if uncertain: status = 'CLEANUP_UNCONFIRMED'
        try:
            if not self.closed:
                self.host.save('result.json',{'schema':1,'token':self.metadata['token'],'original_id':self.original_id,
                                            'ownership_status':status,'native_eligible':False})
        except BaseException:
            uncertain = True
        finally:
            if not self.closed:
                self.closed = True
                try: self.host.close()
                except BaseException: uncertain = True
        if uncertain or status == 'CLEANUP_UNCONFIRMED':
            raise OwnershipUnavailable(cleanup=True)


@contextmanager
def reserve(*,token,image_id,signature_generation,purpose,mode,scenario,phase,source_policy,expected_labels):
    """PUBLIC ownership only. Caller must not inspect/start before durable CID.

    finish receives controller-observed ownership metadata, never native proof.
    No journal file is read to adopt or execute an old container.
    """
    metadata = _metadata(token=token,image_id=image_id,signature_generation=signature_generation,purpose=purpose,
                         mode=mode,scenario=scenario,phase=phase,source_policy=source_policy,expected_labels=expected_labels)
    host = _Host(token); journal = None
    try:
        host.__enter__()
        journal = _Journal(host,metadata)
        journal._save('reservation.json',metadata)
        yield journal
    except BaseException as error:
        if journal is None:
            try: host.close()
            except BaseException: raise OwnershipUnavailable(cleanup=True) from None
            if isinstance(error,OwnershipUnavailable) and error.code == 'OWNERSHIP_CLEANUP_UNCONFIRMED':
                raise OwnershipUnavailable(cleanup=True) from None
            raise OwnershipUnavailable() from None
        raise
    finally:
        if journal is not None and not journal.closed:
            journal.finish('CLEANUP_UNCONFIRMED')
