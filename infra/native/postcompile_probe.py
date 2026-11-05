"""Finite PUBLIC readback diagnostic; import is inert and no scan is performed.

Only the unchanged installed worker constructor accesses native software. This
module observes its existing first failure and never changes engine policy.
"""
from __future__ import annotations

import ctypes
import json
import sys

SCOPE = 'PUBLIC_POSTCOMPILE_READBACK_DIAGNOSTIC_ONLY'
FIELDS = frozenset(('0','1','2','3','14','15','17','23','25','26','31','32','33','34'))
EXPECTED = {'0':33554432,'1':5242880,'2':4,'3':32,'14':0,'15':1,'17':2,
            '23':0,'25':1,'26':4,'31':60000,'32':100000,'33':1000,'34':5242880}
MODES = {0:'AUTO',1:'JIT',2:'INTERPRETER',3:'TEST',4:'OFF'}
FAILURES = frozenset(('UNCLASSIFIED','CONFIGURATION_REFUSED','CLEANUP_FAILED','WORKER_UNAVAILABLE'))
COMMON = frozenset(('GETTER_ERROR','INVALID_TYPE','UNKNOWN'))
MAX_RESULT = 4096


class ProbeUnavailable(ValueError):
    def __str__(self): return 'PUBLIC_POSTCOMPILE_DIAGNOSTIC_UNAVAILABLE'


def _require(value):
    if value is not True: raise ProbeUnavailable()


def _result(observation, field='NONE', category='NONE'):
    return {'schema':1,'scope':SCOPE,'completed':observation in ('FIRST_MISMATCH','NO_MISMATCH'),
            'observation':observation,'field':field,'category':category,
            'native_eligible':False,'private_input_allowed':False}


def classify(error, worker):
    """Observe only the original exact code frame; never traverse error chains."""
    try:
        _require(isinstance(error, BaseException))
        code = worker.NativeScanner._check_limits.__code__
        frame = error.__traceback__; matched = None
        for _ in range(32):
            if frame is None: break
            if frame.tb_frame.f_code is code:
                _require(matched is None); matched = frame.tb_frame
            frame = frame.tb_next
        _require(frame is None and matched is not None)
        # These are the ONLY traceback local names read. Never enumerate,
        # serialize, stringify or return the frame or any arbitrary value.
        local = matched.f_locals
        field = local.get('field'); observed = local.get('observed'); flag = local.get('error')
        _require(type(field) is str and field in FIELDS and type(flag) is ctypes.c_int)
        status = flag.value
        _require(type(status) is int)
        if status != 0: category = 'GETTER_ERROR'
        elif type(observed) is not int: category = 'INVALID_TYPE'
        else:
            _require(observed != EXPECTED[field])
            category = MODES.get(observed, 'UNKNOWN') if field == '17' else 'VALUE_MISMATCH'
        return _result('FIRST_MISMATCH',field,category)
    except Exception:
        return _result('UNCLASSIFIED')


def run(worker):
    """Construct once, record finite mismatch, then require final cleanup.

    The real constructor owns cleanup on initialization failure. Its cleanup
    exception has a different original traceback; chained old failures are not
    accepted. A successful constructor is closed here before NO_MISMATCH.
    """
    scanner = None; result = _result('UNCLASSIFIED'); configured = False
    try:
        worker.load_configuration(); configured = True
        scanner = worker.NativeScanner()
        result = _result('NO_MISMATCH')
    except Exception as error:
        result = classify(error,worker) if configured else _result('CONFIGURATION_REFUSED')
    finally:
        try:
            if scanner is not None: scanner.close()
        except BaseException:
            result = _result('CLEANUP_FAILED')
        try:
            worker._scratch_empty()
        except BaseException:
            result = _result('CLEANUP_FAILED')
    return parse_result(json.dumps(result,separators=(',',':')).encode('ascii'))


def parse_result(raw):
    """Closed diagnostic schema, never a strict/PCRE/native readiness frame."""
    def pairs(items):
        result = {}
        for key,value in items:
            _require(key not in result); result[key] = value
        return result
    try:
        _require(type(raw) is bytes and 1 <= len(raw) <= MAX_RESULT)
        doc = json.loads(raw.decode('ascii'),object_pairs_hook=pairs,
                         parse_constant=lambda _: _require(False))
        _require(type(doc) is dict and set(doc) == {'schema','scope','completed','observation','field','category','native_eligible','private_input_allowed'})
        _require(type(doc['schema']) is int and doc['schema'] == 1 and type(doc['scope']) is str and doc['scope'] == SCOPE and
                 type(doc['completed']) is bool and doc['native_eligible'] is False and doc['private_input_allowed'] is False)
        observation,field,category = doc['observation'],doc['field'],doc['category']
        _require(type(observation) is str and type(field) is str and type(category) is str)
        if observation == 'FIRST_MISMATCH':
            _require(doc['completed'] is True and field in FIELDS)
            allowed = COMMON|set(MODES.values()) if field == '17' else COMMON|{'VALUE_MISMATCH'}
            _require(category in allowed)
            # The exact expected interpreter readback cannot itself be the
            # first mismatch. Getter errors have their own finite category.
            _require(category != 'INTERPRETER')
        elif observation == 'NO_MISMATCH':
            _require(doc['completed'] is True and field == 'NONE' and category == 'NONE')
        else:
            _require(observation in FAILURES and doc['completed'] is False and field == 'NONE' and category == 'NONE')
        return doc
    except (ValueError,TypeError,UnicodeError,RecursionError,KeyError):
        raise ProbeUnavailable() from None


def main():
    if len(sys.argv) != 1: return 2
    try:
        from kapit_evidence import evidence_native_worker as worker
        result = run(worker)
    except BaseException:
        result = _result('WORKER_UNAVAILABLE')
    print(json.dumps(result,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False))
    return 0 if result['completed'] else 2


if __name__ == '__main__':raise SystemExit(main())
