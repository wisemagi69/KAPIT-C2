import unittest
from infra import evidence_release_schemas as s
from infra.tests.test_release_bridge import fixture

class SchemaTests(unittest.TestCase):
    def setUp(self): self.policy,self.bundle,self.sources,self.sign=fixture()
    def test_all_fixture_documents(self):
        s.parse("POLICY",self.policy)
        for name,value in self.bundle.items():
            kind={"AP":"A","AD":"A","WP":"W","WD":"W","P":"RECEIPT","D":"RECEIPT"}.get(name,name)
            if name.endswith("authority") or name.endswith("review"): kind="RECORD"
            if type(value) is tuple:
                s.parse(kind,value[0]); s.parse("AUTH" if kind=="E" else "SIGNATURE",value[1])
            else: s.parse(kind,value)
    def test_malformed_privacy(self):
        for raw in (b'{"secret":"canary",',b'{"schema":2,"schema":2}',b'\xef\xbb\xbf{}',b'{}x',b'[]',b'{"x":NaN}',b'{"x":1.0}',b' '*262145,b''):
            with self.subTest(length=len(raw)):
                with self.assertRaises(s.Refused) as caught: s.parse("S",raw)
                self.assertIsNone(caught.exception.__context__); self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(str(caught.exception),"RELEASE_BRIDGE_REFUSED")
    def test_nested_duplicates(self):
        with self.assertRaises(s.Refused): s.parse("S",b'{"runtime":{"x":1,"x":2}}')
    def test_ascii_utc_every_boundary(self):
        for value in ("٢٠٢٦-10-23T15:00:00Z","2026-1-23T15:00:00Z","2026-10-23T15:00:00+00:00","2026-02-30T15:00:00Z"):
            with self.assertRaises(s.Refused): s.utc(value)
        policy=s.parse("POLICY",self.policy).view()
        for field in ("not_before_utc","not_after_utc"):
            changed=s.parse("POLICY",self.policy).view(); changed["keys"][0][field]="٢٠٢٦-10-23T15:00:00Z"
            with self.assertRaises(s.Refused): s.parse("POLICY",s.canonical(changed))
    def test_bool_integer_type_confusion(self):
        subject=s.parse("S",self.bundle["S"]).view(); subject["subject_version"]=True
        with self.assertRaises(s.Refused): s.parse("S",s.canonical(subject))
        auth=s.parse("AH",self.bundle["AH"][0]).view(); auth["budgets"]["containers_created"]=False
        with self.assertRaises(s.Refused): s.parse("AH",s.canonical(auth))
    def test_unknown_and_reordered_components(self):
        subject=s.parse("S",self.bundle["S"]).view(); subject["components"].reverse()
        with self.assertRaises(s.Refused): s.parse("S",s.canonical(subject))
        subject=s.parse("S",self.bundle["S"]).view(); subject["extra"]=False
        with self.assertRaises(s.Refused): s.parse("S",s.canonical(subject))
    def test_immutable_document_fresh_view(self):
        document=s.parse("S",self.bundle["S"]); view=document.view(); view["components"].clear()
        self.assertEqual(len(document.view()["components"]),4)
        with self.assertRaises(Exception): document.raw=b"{}"
    def test_deep_and_noncanonical(self):
        for raw in (b'['*30+b'0'+b']'*30,self.bundle["S"]+b'\n',self.bundle["S"].replace(b':',b': ',1)):
            with self.assertRaises(s.Refused): s.parse("S",raw)

if __name__ == "__main__": unittest.main()
