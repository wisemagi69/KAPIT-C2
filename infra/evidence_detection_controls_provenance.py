"""Fixed diagnostic metadata and protected historical lineage, never live clearance.

The future caller must authenticate the bootstrap reader, this module and its
controller, and retain the outer protected locks and ExitStack through use.
"""
from dataclasses import asdict, dataclass
import hashlib
from itertools import islice
import json
import re

PINNED_INPUTS = (('infra/native/strict_probe.py', '021d12e778a40bb2f6e3820ec2055d0a4149882a3a2b0438924dcecf38a1c078'), ('infra/evidence_rmdir_native.py', '8c45db9e71e67656bdb20fb47c008d4c9419c7664e40010ef2adbbc5fc5deed0'), ('infra/evidence_rmdir_proof.py', '875cc59993b130316da12e1ba42c7580d4752e3e50d993f2673bcac64bef5acb'), ('infra/evidence_rmdir_profile.py', '73300666b534c7fe1d36140ea7d28464c2ececaf1ab520f2c7afa483c4ecbbfc'), ('infra/evidence_rmdir_diagnostic.py', '488c2b810b14e76f90ca5a1bf77e2599511d38cdcee51537d01908a0277b174f'), ('ai/state/private-scanner-rmdir-proof-strict.json', '793cc6f8c063451de4205f24ba6d7da1eb9e3db4016915771d53c9b6ca56632b'), ('ai/state/private-scanner-rmdir-proof-confinement.json', '38bb820b726ccdd63aee03048c18094eceeaaa0286352afda3e8e084e70fe59f'), ('ai/state/private-scanner-rmdir-proof-preflight.json', 'c28e6af994b05eb2f0fcbe6a5a461faafff165efb8f070c0117987d2bd767ed6'), ('ai/state/private-scanner-rmdir-prepare.json', '6794cfea93e71d39b4df6610be73f2a838f165350e8f61c94dff39fac98d184c'), ('ai/state/private-scanner-rmdir-preflight.json', 'b2188bdb777b3cbd151200bd5935959333f6d8de8eb0447c196e6e39cfb5f1b6'), ('ai/state/private-scanner-rmdir-rmdir.json', '2d30584ea4a7fc6ead0ef97d6af6ec1d3e25d5de50835e8b57c4ef27dcc36a66'), ('ai/state/private-scanner-rmdir-lifecycle.json', 'daebe1ab66825446eb7eef4dee6e67eedf2327fb1531b3f4824967087e947ba0'), ('infra/evidence_strict_failure_details.py', '53e1659253f48c69c7b4b11b8cdc1be758e58a123965198bb2ed87264868cd17'), ('infra/tests/test_strict_failure_details.py', 'ee0450ad68078118f56368531e9c860801394beab53a8e4d8c9584ed633b81e0'), ('infra/evidence_strict_identity_native.py', '09541b9b06aa0cb542060189a00c332e376ed0ade43a6a3c30c4d0cce224c702'), ('infra/evidence_strict_identity_provenance.py', 'bbed594d3a4df209da52fd7c2047f9d6440f21dab6e74ab1ce2628d2955ed41e'), ('infra/evidence_strict_identity_controller.py', '57f6ce840525cc3b7103f12c76f607e3d855a5144531593125036b8a172c6a75'), ('infra/tests/test_strict_identity_native.py', 'e6aeeb20e0d685eb46afcdbbcc285ee348a8bdc5be06e9a1c4677bc2875b5508'), ('infra/tests/test_strict_identity_provenance.py', 'c2166aab803e717fbbf94e5e8e7145f61e669885a7a85dc115aa77978cbcb60f'), ('infra/tests/test_strict_identity_controller.py', 'bcab5e5647ef50e72182712004b1c1235e786e540277ed54d597bf6a9a99970b'), ('ai/state/private-scanner-strict-identity-preflight.json', 'b4eb091896576885764c22061a14f4a4ebbceac70a4e2b435728fe883447d5e7'), ('ai/state/private-scanner-strict-identity-diagnostic.json', '7edef22ef4cfc4f88511cf72613c08cf8ac8f9dd8a6e7570d834dc4f44993f00'), ('infra/evidence_strict_failure_categories.py', 'dd3ee21ba230ac2b3b47b0b700bf3ebff73dc1e6f2043d1c52fe49a39376fcf7'), ('infra/tests/test_strict_failure_categories.py', '3d1509b474d686df86c960abfa78f2cddca411df21b6e5c09f4a41ac668eebdb'), ('infra/evidence_strict_category_native.py', 'ca07edf6d213f487bbd904aff1f0c922188bba49b3d183f725141fe884ea1906'), ('infra/evidence_strict_category_provenance.py', '4c0e432cbd6956c6525cd39aede199d041f28e11e46820d1b624d416c02948bb'), ('infra/evidence_strict_category_controller.py', '9a79b57949712f82990c323e3ca617f6a26170c0adfa10957de3d06102d1c671'), ('infra/tests/test_strict_category_native.py', 'cf0379a03f6c9ccba62e554327b6db8819ac054276a6bd1d4004f5bb60a78909'), ('infra/tests/test_strict_category_provenance.py', '7f8ee1bdea923e9dff4cac5e492b790c560d42d70304d40af4737e6b2d972350'), ('infra/tests/test_strict_category_controller.py', '5dfb84b182c0f4bfb68fd595c2db73ec0923a39bf2e48c8ace3f338a4c65c616'), ('ai/state/private-scanner-strict-category-preflight.json', '71c9569d33ce61aa9833bb6820514f8552db120de56e29794cf616f70ab2e973'), ('infra/evidence_strict_category_v2_native.py', 'eac33f8f4efc387878181b06d6041a8c6bc5621ee343be862e6cd1027739d40c'), ('infra/evidence_strict_category_v2_provenance.py', '2765f686193f6bce18f20aeed450a4cc83c5e277b38eacd6b4dc5da53190366c'), ('infra/evidence_strict_category_v2_controller.py', '0ad4d0bed59de2a5e6de25573ace28c8a7162e59baea008358cf38db0f1c9134'), ('infra/tests/test_strict_category_v2_native.py', '2c7bc937535717017a991642efaaabc17ffbfe19afc5e2bdfdbad7f9b64a5748'), ('infra/tests/test_strict_category_v2_provenance.py', '159a072d48829ae670564884d1e2dc2a2a535ea106dd449fcc1519fe91aa2b84'), ('infra/tests/test_strict_category_v2_controller.py', '6f28b4e86288924e747807c94931625a297bc8b1596d69fbb61a53783aaf2796'), ('docs/scanner-detection-control-plan.md', 'd15e2b5a0790e001490b7b8823b628e82711d5def4a612be32715533fa0f24dc'), ('ai/reports/security-detection-control-plan.md', '2da5810b59f600104f2959a8d80c2727e126c5893cdf6db6c310e618d17a4984'), ('ai/reports/scanner-category-diagnostic-integration.json', 'e1a4a3adfc7e2282e6e974d5f3a6b911b2aaaf8bca0057a165e7e98f1074f34b'), ('ai/reports/devops-category-cause-audit.md', '81f80d2cde2e7b00255fb2d47e754b61d170d4a7b0a38bb436b4716b81e7aa20'), ('ai/state/private-scanner-strict-category-v2-preflight.json', 'f360b5e4e2cfce59cca8f7c9397e49e9f0fb48ce025546b8cc36f4e0c6c3cd0a'), ('ai/state/private-scanner-strict-category-v2-diagnostic.json', '896d45b92c1db7ce640539ed9fff9fac017266c628b9839eb56b0f396eb02f7f'), ('infra/evidence_detection_controls.py', '137ebe3fcc2458e5ef56b4989371236385b0ab2fa4038812b24b9a7aa7336c03'), ('infra/tests/test_detection_controls.py', '3f930964a0127373913af1123cddf611411cc780fdf81f7a03209f10b60dceac'), ('ai/reports/detection-controls-parser-integration.json', 'cf2c3a338e26312a940b02058b3ba91e3bce4eb57e740f30bf72a36428a4f878'), ('ai/reports/qa-detection-controls-parser.md', '429ea5c7d1a8777e59671acab382dc1c9a8727397930339401a51bbf35faa2e0'), ('ai/reports/security-detection-controls-parser.md', 'eb0f83654fb69137c50283e22a5cd212c4af5338a43721bb9e979c2a5d3d9213'), ('backend/apps/operations/evidence_native_worker.py', '3cebed0fbccb579dc6890f28071b80936d194876c69957eb4820f2564713c991'), ('infra/native/detection_controls_probe.py', '1da130bb36efcf1763b8de439164596ea0d8af659dd53188f0b1099c44088677'), ('infra/tests/test_detection_controls_probe.py', '8b14ea4a6384eb4ab30b2662c48223ac5fca1d9b6f9cf92d19620d84da00511d'), ('ai/reports/detection-controls-program-integration.json', '7ba8ce6048eb2c9d6d94c72a820a68584c84f6e9abc37369e2351afa0e7ac6d1'), ('ai/reports/security-detection-controls-program.md', 'e49e22e5c81ad8599c9f46ed0edaa828e30e26d6ecaa0c28ec650145047e291e'), ('ai/reports/qa-detection-controls-program.md', 'c8e3799d2708b285625912470d789eaea907717bfaf923229779fdad59ef2610'))

_RECEIPT = 'ai/state/private-scanner-strict-category-v2-diagnostic.json'
_PREFLIGHT = 'ai/state/private-scanner-strict-category-v2-preflight.json'
_V1 = 'ai/state/private-scanner-strict-category-preflight.json'
_CONTROLLER = 'infra/evidence_strict_category_v2_controller.py'
_FIELDS = ('image_id', 'signature_generation', 'profile_sha256', 'preparation_sha256',
           'probe_sha256', 'parser_sha256', 'consumed_receipt_sha256', 'contract')
_FIXED = (
    'sha256:e9bec5b6efb3e30d84b449b7cfa13ec47a3408f775b723c02fdfe3c2a909c8aa',
    '1f52a88b3cc78594af3934591bb9c1f5ef8672c2b0f25bf336e41c1306dc21f3',
    'b3b2f13c2e2c92b6674531c8aa6ae0d95209ba48db812a3774d14a209574c733',
    '098e8ea0369cdb76d0dc66552f1f210c47acbd9b8d24fc6d0c2a32b68bba429f',
    dict(PINNED_INPUTS)['infra/native/detection_controls_probe.py'],
    dict(PINNED_INPUTS)['infra/evidence_detection_controls.py'],
    dict(PINNED_INPUTS)[_RECEIPT],
)
# Versioned, deterministic description of metadata/replay inputs, not a seal
# authenticating this module or any future controller.
_CONTRACT_DOCUMENT = ('PUBLIC_DETECTION_CONTROL_SOURCE_LINEAGE_V1', _FIELDS[:-1],
                      _FIXED, PINNED_INPUTS, 28, 112, 256,
                      'UNKNOWN_RESERVATIONS_REFUSE_WITHOUT_OWNER_OR_IMAGE_FILTER')
CONTRACT = hashlib.sha256(json.dumps(_CONTRACT_DOCUMENT, separators=(',', ':')).encode('ascii')).hexdigest()


class ProvenanceUnavailable(RuntimeError):
    def __init__(self):
        super().__init__('PUBLIC_DETECTION_CONTROL_PROVENANCE_UNAVAILABLE')


def _require(condition):
    if condition is not True:
        raise ProvenanceUnavailable()


@dataclass(frozen=True, slots=True)
class _Binding:
    image_id: str
    signature_generation: str
    profile_sha256: str
    preparation_sha256: str
    probe_sha256: str
    parser_sha256: str
    consumed_receipt_sha256: str
    contract: str


def binding():
    """Fresh fixed immutable metadata; no run permit or currentness assertion."""
    return _Binding(*_FIXED, CONTRACT)


def binding_fields(value):
    """Return a fresh closed projection only for the exact fixed binding."""
    failed = False
    result = None
    try:
        _require(type(value) is _Binding)
        result = asdict(value)
        _require(tuple(result) == _FIELDS and
                 all(type(item) is str for item in result.values()) and value == binding())
    except BaseException:
        failed = True
    if failed:
        raise ProvenanceUnavailable()
    return result


def _pin_sources(root, pins, api):
    # This reader is the established bootstrap dependency. Its own outer
    # authentication is mandatory in the future independently reviewed caller.
    from infra import evidence_interpreter_runtime as current
    for path, expected in PINNED_INPUTS:
        current.pin_bytes(root, pins, api, path, expected=expected, maximum=262144)
    # No inherited category validator import precedes the complete manifest.
    from infra import evidence_strict_category_v2_controller as controller
    inherited_binding = controller.binding(dict(PINNED_INPUTS)[_CONTROLLER])
    provenance = controller._pin_sources(root, pins, api, inherited_binding)
    return current, controller, provenance, inherited_binding


def pin_sources(root, pins, api):
    """Pin fixed/transitive inputs in caller's stack, returning metadata only."""
    failed = False
    try:
        _pin_sources(root, pins, api)
    except BaseException:
        failed = True
    if failed:
        raise ProvenanceUnavailable()
    return binding()


def _validate_consumed(value, controller, expected):
    controller._validate_diagnostic_receipt(value, expected)
    _require(value['status'] == 'MEASURED' and value['completed'] is True
             and value['finalizers'] == {name: 'CONFIRMED' for name in controller.FINALIZERS}
             and all(value[name] is False for name in
                     ('native_eligible', 'private_input_allowed', 'control_state_modified')))
    observation = value['observation']
    details = observation['details']
    _require(observation['observed'] is True and details['completed'] is True
             and type(details['case_count']) is int and details['case_count'] == 14
             and details['failed_case_ids'] == ['eicar_png']
             and details['failed_cases'] == [{'case': 'eicar_png', 'strict': 'CLEAN',
                 'upstream': 'CLEAN', 'normalization_observed': False}]
             and details['failed_cases'][0]['normalization_observed'] is False)


def _row_set(rows):
    names = {'reservation.json', 'create-attempt.json', 'ownership.json', 'result.json'}
    _require(type(rows) is list and len(rows) == 28)
    _require(all(type(row) is dict and type(row['token']) is str
                 and re.fullmatch('[0-9a-f]{32}', row['token']) is not None
                 and type(row['original_id']) is str
                 and re.fullmatch('[0-9a-f]{64}', row['original_id']) is not None
                 and type(row['files']) is dict and set(row['files']) == names for row in rows))
    _require(len({row['token'] for row in rows}) == 28
             and len({row['original_id'] for row in rows}) == 28
             and sum(len(row['files']) for row in rows) == 112)


def _reservations(root, pins, api, rows, current, diagnostic):
    from infra.live_recovery_drill import PrivateDirectory
    _row_set(rows)
    allowed = {row['token']: row['files']['reservation.json']['document'] for row in rows}
    directories = list(islice((root / diagnostic.STAGE).glob('native-run-*'), 257))
    _require(len(directories) <= 256)
    seen = set()
    for directory in directories:
        _require(re.fullmatch('native-run-[0-9a-f]{32}', directory.name) is not None)
        token = directory.name[11:]
        _require(token not in seen)
        seen.add(token)
        pins.enter_context(PrivateDirectory().pin(directory, private=True, directory=True))
        raw = current.pin_bytes(root, pins, api,
            (directory / 'reservation.json').relative_to(root).as_posix(), private=True, maximum=8192)
        value = current.document(raw)
        # No owner/image filter: every discovered reservation must be known.
        _require(token in allowed and type(value) is dict and value == allowed[token])
        canonical = json.dumps(allowed[token], sort_keys=True, separators=(',', ':')).encode('utf-8')
        _require(type(raw) is bytes and raw == canonical)
    _require(seen == set(allowed))


def preserved_originals(root, pins, api, prepared):
    """Replay exact historical originals, never query live absence or create."""
    failed = False
    rows = None
    try:
        current, controller, provenance, expected = _pin_sources(root, pins, api)
        value = current.document(current.pin_bytes(root, pins, api, _RECEIPT,
            expected=dict(PINNED_INPUTS)[_RECEIPT], maximum=262144))
        _validate_consumed(value, controller, expected)
        # Explicitly preserve the inherited v1 refusal and its uncertainty.
        provenance.validate_v1_preflight(current.document(current.pin_bytes(root, pins, api,
            _V1, expected=dict(PINNED_INPUTS)[_V1], maximum=262144)))
        current.pin_bytes(root, pins, api, _PREFLIGHT,
            expected=dict(PINNED_INPUTS)[_PREFLIGHT], maximum=262144)
        preflight = controller.preflight_provenance(root, pins, api, expected)
        _require(preflight['preserved_originals'] == value['preserved_originals'])
        rows = controller._postflight_originals(root, pins, api, expected, prepared)
        _row_set(rows)
        from infra import evidence_rmdir_diagnostic as diagnostic
        _reservations(root, pins, api, rows, current, diagnostic)
    except BaseException:
        failed = True
    if failed:
        raise ProvenanceUnavailable()
    return rows
