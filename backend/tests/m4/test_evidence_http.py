"""Real numeric-loopback session/CSRF quarantine HTTP; parent runs disposable DB.

No force-authentication, response fixtures, native verdicts or application server
reuse. LiveServerTestCase owns its ephemeral listener and normal cleanup.
"""
import json
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request
import uuid

from cryptography.fernet import Fernet
from django.core.management import call_command
from django.db import connection
from django.test import LiveServerTestCase, override_settings

from apps.operations.models import PrivateEvidence, PrivateEvidenceValidation, ProcessingJob, SyncReceipt
from apps.publications.models import Publication
from apps.reports.models import ReportRevision
from apps.review.models import ReviewDecision
from tests.m4.test_evidence_decoder import png
from tests.test_workflow import operation


IMAGE = png()
FILENAME = 'PRIVATE_EVIDENCE_HTTP_CANARY.png'
META_KEYS = {'id', 'operation_id', 'state', 'validation_code', 'created_at'}
NOT_FOUND = {'code': 'NOT_FOUND', 'message': 'This item is unavailable.'}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Session:
    """Only this LiveServer's exact numeric origin, cookies and bounded bodies."""
    def __init__(self, case):
        self.case = case
        self.origin = case.live_server_url
        parsed = urlsplit(self.origin)
        case.assertEqual((parsed.scheme, parsed.hostname), ('http', '127.0.0.1'))
        case.assertTrue(type(parsed.port) is int and parsed.port > 0)
        self.jar = CookieJar()
        self.opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(self.jar), NoRedirect())
        self.token = None

    def request(self, path, *, method='GET', body=None, media='application/json', csrf=True, headers=None):
        self.case.assertTrue(path.startswith('/api/v1/') and not path.startswith('//'))
        values = {'Accept': 'application/json', 'Origin': self.origin}
        if body is not None:
            values['Content-Type'] = media
        if csrf and self.token is not None:
            values['X-CSRFToken'] = self.token
        values.update(headers or {})
        request = Request(self.origin + path, data=body, headers=values, method=method)
        try:
            try:
                response = self.opener.open(request, timeout=15)
            except HTTPError as error:
                response = error
            with response:
                raw = response.read(65537)
                self.case.assertLessEqual(len(raw), 65536, 'HTTP response exceeded fixed test bound')
                status = response.code
                response_headers = {key.lower(): value for key, value in response.headers.items()}
        except (URLError, OSError):
            raise AssertionError('Owned loopback HTTP request failed') from None
        try:
            document = json.loads(raw)
        except (ValueError, UnicodeError):
            raise AssertionError('Expected bounded JSON response') from None
        return status, document, response_headers, raw

    def login(self, username):
        status, document, _, _ = self.request('/api/v1/auth/csrf/')
        self.case.assertEqual(status, 200)
        self.token = document['csrf_token']
        status, _, _, _ = self.request('/api/v1/auth/login/', method='POST', body=json.dumps({
            'username': username, 'password': 'DemoMaintenance!2026'}).encode())
        self.case.assertEqual(status, 200)
        # Login rotates the CSRF secret; obtain the actual post-login token.
        status, document, _, _ = self.request('/api/v1/auth/csrf/')
        self.case.assertEqual(status, 200)
        self.token = document['csrf_token']
        self.case.assertTrue(any(cookie.name == 'sessionid' for cookie in self.jar))
        status, document, _, _ = self.request('/api/v1/me/')
        self.case.assertEqual(status, 200)
        self.case.assertEqual(document['user']['username'], username)
        return self

    def upload(self, revision_id, operation_id, *, data=IMAGE, filename=FILENAME, csrf=True, headers=None):
        values = {'Idempotency-Key': str(operation_id), 'X-Evidence-Filename': filename}
        values.update(headers or {})
        return self.request(f'/api/v1/revisions/{revision_id}/evidence/', method='POST',
                            body=data, media='image/png', csrf=csrf, headers=values)


@override_settings(KAPIT_SOURCE_KEY=Fernet.generate_key(), ROOT_URLCONF='config.urls',
                   PASSWORD_HASHERS=['django.contrib.auth.hashers.MD5PasswordHasher'],
                   DEBUG=False, ALLOWED_HOSTS=['127.0.0.1'], CSRF_TRUSTED_ORIGINS=[])
class EvidenceLoopbackHTTPTests(LiveServerTestCase):
    host = '127.0.0.1'

    def setUp(self):
        self.assertEqual(connection.vendor, 'postgresql', 'Requires guarded disposable PostgreSQL')
        call_command('seed_demo', verbosity=0)

    def submit(self):
        author = Session(self).login('submitter')
        body = operation()
        status, receipt, _, _ = author.request('/api/v1/sync/operations/', method='POST',
            body=json.dumps(body).encode(), headers={'Idempotency-Key': body['operation_id']})
        self.assertEqual(status, 201)
        self.assertEqual(receipt['delivery_status'], 'RECEIVED')
        self.assertEqual(receipt['processing_status'], 'PENDING')
        self.assertIs(receipt['shared'], False)
        return author, body, receipt

    def private_absent(self, raw):
        # Avoid embedding a leaked response in assertion failure output.
        for value in (IMAGE, FILENAME.encode(), b'bytes_base64', b'payload_ciphertext',
                      b'input_sha256', b'derivative_ciphertext', b'PRIVATE_NARRATIVE_CANARY'):
            self.assertTrue(value not in raw, 'Private value appeared in HTTP response')

    def test_real_login_upload_exact_replay_and_private_quarantine_status(self):
        author, body, receipt = self.submit()
        key = uuid.uuid4()
        first = author.upload(receipt['revision_id'], key)
        again = author.upload(receipt['revision_id'], key)
        self.assertEqual((first[0], again[0]), (201, 200))
        self.assertEqual(set(first[1]), META_KEYS)
        self.assertEqual(first[1], again[1])
        self.assertEqual(first[1]['operation_id'], str(key))
        self.assertEqual((first[1]['state'], first[1]['validation_code']), ('QUARANTINED', 'DECODER_REQUIRED'))
        self.assertIn('no-store', first[2].get('cache-control', ''))
        evidence_id = first[1]['id']
        metadata = author.request(f'/api/v1/evidence/{evidence_id}/')
        self.assertEqual((metadata[0], metadata[1]), (200, first[1]))
        status = author.request(f'/api/v1/evidence/{evidence_id}/validation/')
        self.assertEqual(status[0], 200)
        self.assertEqual(status[1], {'evidence_id': evidence_id, 'state': 'QUARANTINED',
                                    'validation_code': 'DECODER_REQUIRED', 'can_download': False})
        self.assertIn('no-store', status[2].get('cache-control', ''))
        conflict = author.upload(receipt['revision_id'], key, filename='different.png')
        self.assertEqual((conflict[0], conflict[1]['code']), (409, 'IDEMPOTENCY_CONFLICT'))
        for attempted in (evidence_id, uuid.uuid4()):
            denied = author.request(f'/api/v1/evidence/{attempted}/download/')
            self.assertEqual((denied[0], denied[1]), (404, NOT_FOUND))
            self.private_absent(denied[3])
        for response in (first, again, metadata, status, conflict):
            self.private_absent(response[3])
        later = author.request(f"/api/v1/sync/receipts/{body['operation_id']}/")
        self.assertEqual((later[0], later[1]), (200, receipt))
        self.assertEqual((PrivateEvidence.objects.count(), PrivateEvidenceValidation.objects.count()), (1, 0))
        self.assertEqual((ReportRevision.objects.count(), SyncReceipt.objects.count(), ProcessingJob.objects.count()), (1, 1, 1))
        self.assertEqual(ProcessingJob.objects.get().status, 'PENDING')
        self.assertEqual((ReviewDecision.objects.count(), Publication.objects.count()), (0, 0))

    def test_reviewer_read_only_and_recipient_admin_unknown_uniform_denials(self):
        author, _, receipt = self.submit()
        status, metadata, _, _ = author.upload(receipt['revision_id'], uuid.uuid4())
        self.assertEqual(status, 201)
        evidence_id = metadata['id']
        reviewer = Session(self).login('reviewer')
        response = reviewer.request(f'/api/v1/evidence/{evidence_id}/')
        self.assertEqual((response[0], response[1]), (200, metadata))
        response = reviewer.request(f'/api/v1/evidence/{evidence_id}/validation/')
        self.assertEqual(response[0], 200)
        self.assertEqual((response[1]['state'], response[1]['validation_code'], response[1]['can_download']),
                         ('QUARANTINED', 'DECODER_REQUIRED', False))
        self.private_absent(response[3])
        for revision in (receipt['revision_id'], uuid.uuid4()):
            response = reviewer.upload(revision, uuid.uuid4())
            self.assertEqual((response[0], response[1]), (404, NOT_FOUND))
        for username in ('recipient', 'administrator'):
            session = Session(self).login(username)
            for suffix in ('', 'validation/', 'download/'):
                for attempted in (evidence_id, uuid.uuid4()):
                    response = session.request(f'/api/v1/evidence/{attempted}/{suffix}')
                    self.assertEqual((response[0], response[1]), (404, NOT_FOUND))
                    self.private_absent(response[3])
            for revision in (receipt['revision_id'], uuid.uuid4()):
                response = session.upload(revision, uuid.uuid4())
                self.assertEqual((response[0], response[1]), (404, NOT_FOUND))
                self.private_absent(response[3])
        self.assertEqual(PrivateEvidence.objects.count(), 1)
        self.assertEqual(PrivateEvidenceValidation.objects.count(), 0)

    def test_real_csrf_origin_and_distinct_binary_json_caps_preserve_text_receipt(self):
        anonymous = Session(self)
        status, _, _, _ = anonymous.request('/api/v1/auth/login/', method='POST', csrf=False,
            body=json.dumps({'username': 'submitter', 'password': 'DemoMaintenance!2026'}).encode())
        self.assertEqual(status, 403)
        author, body, receipt = self.submit()
        for options in ({'csrf': False}, {'headers': {'Origin': 'http://127.0.0.1'}}):
            # Omitting the real ephemeral port is a different, untrusted origin.
            response = author.upload(receipt['revision_id'], uuid.uuid4(), **options)
            self.assertEqual(response[0], 403)
            self.private_absent(response[3])
        too_large = author.upload(receipt['revision_id'], uuid.uuid4(), data=b'x' * (5242880 + 1))
        self.assertEqual((too_large[0], too_large[1]['code']), (413, 'REQUEST_TOO_LARGE'))
        oversized_json = author.request('/api/v1/sync/operations/', method='POST', body=b' ' * (20 * 1024 + 1),
                                        headers={'Idempotency-Key': str(uuid.uuid4())})
        self.assertEqual((oversized_json[0], oversized_json[1]['code']), (413, 'REQUEST_TOO_LARGE'))
        self.assertEqual(PrivateEvidence.objects.count(), 0)
        self.assertEqual((SyncReceipt.objects.count(), ReportRevision.objects.count()), (1, 1))
        later = author.request(f"/api/v1/sync/receipts/{body['operation_id']}/")
        self.assertEqual((later[0], later[1]), (200, receipt))
        accepted = author.upload(receipt['revision_id'], uuid.uuid4())
        self.assertEqual((accepted[0], accepted[1]['state']), (201, 'QUARANTINED'))
        self.assertEqual((PrivateEvidence.objects.count(), PrivateEvidenceValidation.objects.count()), (1, 0))
        self.assertEqual((ReviewDecision.objects.count(), Publication.objects.count()), (0, 0))
