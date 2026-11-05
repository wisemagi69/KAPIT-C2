"""Reviewed local M1 proposal: PostgreSQL constraints beyond ordinary FKs.

Application owners can disable triggers; this is relational integrity, not a
defense against infrastructure administrators. No generic admin CRUD is exposed.
"""
from django.db import migrations


SQL = r"""
CREATE FUNCTION kapit_org_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  doc jsonb := to_jsonb(NEW);
  owner_id uuid;
  linked_id uuid;
  linked_org uuid;
  i integer;
BEGIN
  owner_id := CASE WHEN TG_TABLE_NAME = 'scopes_organization' THEN NEW.id ELSE (doc->>'organization_id')::uuid END;
  IF TG_OP = 'UPDATE' AND TG_TABLE_NAME <> 'scopes_organization'
     AND doc->>'organization_id' IS DISTINCT FROM to_jsonb(OLD)->>'organization_id' THEN
    RAISE EXCEPTION 'organization ownership is immutable' USING ERRCODE = '23514';
  END IF;
  -- Services and administrative transactions MUST explicitly take this lock
  -- before updating related rows. UPDATE takes a row lock before its trigger,
  -- so this trigger cannot establish org-before-row order by itself.
  PERFORM id FROM scopes_organization WHERE id = owner_id FOR UPDATE;
  IF TG_NARGS > 0 THEN
    FOR i IN 0..TG_NARGS-1 BY 2 LOOP
      linked_id := (doc->>TG_ARGV[i])::uuid;
      IF linked_id IS NOT NULL THEN
        EXECUTE format('SELECT organization_id FROM %I WHERE id = $1', TG_ARGV[i+1]) INTO linked_org USING linked_id;
        IF linked_org IS NULL OR linked_org <> owner_id THEN
          RAISE EXCEPTION 'scope link is inconsistent' USING ERRCODE = '23514';
        END IF;
      END IF;
    END LOOP;
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_frozen_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE old_doc jsonb; new_doc jsonb; i integer;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'retained application records cannot be deleted' USING ERRCODE = '23514';
  END IF;
  old_doc := to_jsonb(OLD); new_doc := to_jsonb(NEW);
  IF TG_NARGS > 0 THEN
    FOR i IN 0..TG_NARGS-1 LOOP
      old_doc := old_doc - TG_ARGV[i]; new_doc := new_doc - TG_ARGV[i];
    END LOOP;
  END IF;
  IF old_doc IS DISTINCT FROM new_doc THEN
    RAISE EXCEPTION 'retained content is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_variant_state_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.state NOT IN ('CANDIDATE', 'APPROVED', 'RETURNED', 'REJECTED') THEN
    RAISE EXCEPTION 'invalid candidate state' USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.state <> NEW.state AND OLD.state <> 'CANDIDATE' THEN
    RAISE EXCEPTION 'a decided candidate cannot be reopened' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_source_link_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE source reports_report%ROWTYPE; revision reports_reportrevision%ROWTYPE; job operations_processingjob%ROWTYPE;
BEGIN
  IF TG_TABLE_NAME = 'reports_reportrevision' THEN
    SELECT * INTO source FROM reports_report WHERE id = NEW.report_id;
    IF NEW.submitted_by_id <> source.author_id OR NEW.revision_no <> source.current_revision_no THEN
      RAISE EXCEPTION 'source revision identity is inconsistent' USING ERRCODE = '23514';
    END IF;
  ELSIF TG_TABLE_NAME = 'operations_syncreceipt' THEN
    SELECT * INTO revision FROM reports_reportrevision WHERE id = NEW.revision_id;
    IF NEW.accepted_user_id <> revision.submitted_by_id OR NEW.operation_id <> revision.operation_id OR NEW.request_hash <> revision.request_hash
       OR NEW.response_body->>'operation_id' IS DISTINCT FROM revision.operation_id::text
       OR NEW.response_body->>'revision_id' IS DISTINCT FROM revision.id::text
       OR NEW.response_body->>'report_id' IS DISTINCT FROM revision.report_id::text
       OR NEW.response_body->'revision_no' IS DISTINCT FROM to_jsonb(revision.revision_no)
       OR NEW.response_body->>'delivery_status' IS DISTINCT FROM 'RECEIVED'
       OR NEW.response_body->>'processing_status' IS DISTINCT FROM 'PENDING'
       OR NEW.response_body->'shared' IS DISTINCT FROM 'false'::jsonb
       OR NOT (NEW.response_body ?& ARRAY['operation_id','report_id','revision_id','revision_no','delivery_status','processing_status','shared'])
       OR (NEW.response_body - ARRAY['operation_id','report_id','revision_id','revision_no','delivery_status','processing_status','shared']) <> '{}'::jsonb THEN
      RAISE EXCEPTION 'acceptance receipt is inconsistent' USING ERRCODE = '23514';
    END IF;
  ELSIF TG_TABLE_NAME = 'reports_reportvariant' THEN
    SELECT * INTO job FROM operations_processingjob WHERE id = NEW.job_id;
    IF NEW.revision_id <> job.revision_id OR NEW.policy_id <> job.policy_id OR NEW.channel_ids <> job.channel_ids OR NEW.profile <> 'DEMO-REDUCED'
       OR NEW.projection->>'profile' IS DISTINCT FROM NEW.profile OR jsonb_typeof(NEW.channel_ids) IS DISTINCT FROM 'array'
       OR jsonb_array_length(NEW.channel_ids) <> 1 OR NEW.candidate_hash !~ '^[a-f0-9]{64}$' THEN
      RAISE EXCEPTION 'candidate processing context is inconsistent' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_revocation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
    RAISE EXCEPTION 'a withdrawn publication cannot be reactivated' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_decision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v reports_reportvariant%ROWTYPE; r reports_reportrevision%ROWTYPE; source reports_report%ROWTYPE; actor accounts_user%ROWTYPE; p scopes_policyversion%ROWTYPE; channels jsonb;
BEGIN
  SELECT * INTO v FROM reports_reportvariant WHERE id = NEW.variant_id;
  SELECT * INTO r FROM reports_reportrevision WHERE id = v.revision_id;
  SELECT * INTO source FROM reports_report WHERE id = r.report_id;
  SELECT * INTO actor FROM accounts_user WHERE id = NEW.reviewer_id;
  SELECT * INTO p FROM scopes_policyversion WHERE id = v.policy_id;
  SELECT coalesce(jsonb_agg(cs.channel_id::text ORDER BY cs.channel_id), '[]'::jsonb) INTO channels
    FROM scopes_channelsource cs JOIN scopes_sharingchannel sc ON sc.id = cs.channel_id JOIN scopes_unit u ON u.id = cs.unit_id
    WHERE cs.unit_id = source.unit_id AND cs.active AND sc.active AND u.active AND cs.organization_id = NEW.organization_id;
  IF actor.role <> 'reviewer' OR NOT actor.is_active OR actor.id = source.author_id OR actor.id = r.submitted_by_id
     OR v.state <> (CASE NEW.action WHEN 'APPROVE' THEN 'APPROVED' WHEN 'RETURN' THEN 'RETURNED' ELSE 'REJECTED' END)
     OR NOT EXISTS (SELECT 1 FROM scopes_unitmembership m JOIN scopes_unit u ON u.id = m.unit_id
                    WHERE m.user_id = actor.id AND m.unit_id = source.unit_id AND m.role = 'reviewer' AND m.active AND u.active
                    AND (m.valid_until IS NULL OR m.valid_until > CURRENT_TIMESTAMP))
     OR NEW.binding->>'revision_id' IS DISTINCT FROM r.id::text
     OR (NEW.binding->>'revision_no')::integer IS DISTINCT FROM r.revision_no
     OR NEW.binding->>'candidate_hash' IS DISTINCT FROM v.candidate_hash
     OR NEW.binding->>'profile' IS DISTINCT FROM v.profile
     OR NEW.binding->'channel_ids' IS DISTINCT FROM v.channel_ids
     OR NEW.binding->>'policy_version' IS DISTINCT FROM p.version
     OR NEW.binding->>'policy_hash' IS DISTINCT FROM p.rules_hash
     OR r.revision_no <> source.current_revision_no OR NOT p.active
     OR v.channel_ids IS DISTINCT FROM channels OR jsonb_array_length(channels) <> 1
     OR NOT EXISTS (SELECT 1 FROM scopes_organization o WHERE o.id = NEW.organization_id AND o.active AND o.active_policy_id = p.id) THEN
    RAISE EXCEPTION 'review decision is inconsistent' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_publication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v reports_reportvariant%ROWTYPE; d review_reviewdecision%ROWTYPE; r reports_reportrevision%ROWTYPE; p scopes_policyversion%ROWTYPE; source reports_report%ROWTYPE;
BEGIN
  SELECT * INTO v FROM reports_reportvariant WHERE id = NEW.variant_id;
  SELECT * INTO d FROM review_reviewdecision WHERE id = NEW.decision_id;
  SELECT * INTO r FROM reports_reportrevision WHERE id = v.revision_id;
  SELECT * INTO p FROM scopes_policyversion WHERE id = v.policy_id;
  SELECT * INTO source FROM reports_report WHERE id = r.report_id;
  IF d.variant_id <> v.id OR d.action <> 'APPROVE' OR v.state <> 'APPROVED'
     OR NEW.report_id <> r.report_id OR NEW.profile <> v.profile OR NEW.projection <> v.projection
     OR NOT (v.channel_ids @> jsonb_build_array(NEW.channel_id::text))
     OR d.binding->>'candidate_hash' IS DISTINCT FROM v.candidate_hash OR d.binding->'channel_ids' IS DISTINCT FROM v.channel_ids
     OR d.binding->>'revision_id' IS DISTINCT FROM r.id::text OR (d.binding->>'revision_no')::integer IS DISTINCT FROM r.revision_no
     OR d.binding->>'policy_version' IS DISTINCT FROM p.version OR d.binding->>'policy_hash' IS DISTINCT FROM p.rules_hash
     OR NOT p.active OR r.revision_no <> source.current_revision_no
     OR NOT EXISTS (SELECT 1 FROM scopes_organization o WHERE o.id = NEW.organization_id AND o.active AND o.active_policy_id = p.id)
     OR NOT EXISTS (SELECT 1 FROM scopes_channelsource c JOIN scopes_sharingchannel sc ON sc.id = c.channel_id JOIN scopes_unit u ON u.id = c.unit_id
                    WHERE c.channel_id = NEW.channel_id AND c.unit_id = source.unit_id AND c.active AND sc.active AND u.active) THEN
    RAISE EXCEPTION 'publication is inconsistent' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER a_org_guard BEFORE UPDATE ON scopes_organization FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('active_policy_id','scopes_policyversion');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON accounts_user FOR EACH ROW EXECUTE FUNCTION kapit_org_guard();
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_unit FOR EACH ROW EXECUTE FUNCTION kapit_org_guard();
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_sharingchannel FOR EACH ROW EXECUTE FUNCTION kapit_org_guard();
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_policyversion FOR EACH ROW EXECUTE FUNCTION kapit_org_guard();
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_unitmembership FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('user_id','accounts_user','unit_id','scopes_unit');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_channelsource FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('channel_id','scopes_sharingchannel','unit_id','scopes_unit');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_channelmember FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('user_id','accounts_user','channel_id','scopes_sharingchannel');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON reports_report FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('author_id','accounts_user','unit_id','scopes_unit');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON reports_reportrevision FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('report_id','reports_report','submitted_by_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON operations_processingjob FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('revision_id','reports_reportrevision','policy_id','scopes_policyversion');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON operations_syncreceipt FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('revision_id','reports_reportrevision','accepted_user_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON reports_reportvariant FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('revision_id','reports_reportrevision','policy_id','scopes_policyversion','job_id','operations_processingjob');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON review_reviewdecision FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('variant_id','reports_reportvariant','reviewer_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON publications_publication FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('variant_id','reports_reportvariant','decision_id','review_reviewdecision','report_id','reports_report','channel_id','scopes_sharingchannel');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON audit_auditevent FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('actor_id','accounts_user');

CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON scopes_policyversion FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard('active');
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON reports_report FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard('current_revision_no');
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON reports_reportrevision FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard('processing_state');
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON operations_processingjob FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard('status','attempts','lease_generation','lease_token','lease_until','available_at','error_code');
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON operations_syncreceipt FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON reports_reportvariant FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard('state');
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON review_reviewdecision FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON publications_publication FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard('revoked_at');
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON audit_auditevent FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER c_variant_state BEFORE INSERT OR UPDATE ON reports_reportvariant FOR EACH ROW EXECUTE FUNCTION kapit_variant_state_guard();
CREATE TRIGGER c_source_link BEFORE INSERT ON reports_reportrevision FOR EACH ROW EXECUTE FUNCTION kapit_source_link_guard();
CREATE TRIGGER c_source_link BEFORE INSERT ON operations_syncreceipt FOR EACH ROW EXECUTE FUNCTION kapit_source_link_guard();
CREATE TRIGGER c_source_link BEFORE INSERT ON reports_reportvariant FOR EACH ROW EXECUTE FUNCTION kapit_source_link_guard();
CREATE TRIGGER c_decision_guard BEFORE INSERT ON review_reviewdecision FOR EACH ROW EXECUTE FUNCTION kapit_decision_guard();
CREATE TRIGGER c_publication_guard BEFORE INSERT ON publications_publication FOR EACH ROW EXECUTE FUNCTION kapit_publication_guard();
CREATE TRIGGER c_revocation_guard BEFORE UPDATE ON publications_publication FOR EACH ROW EXECUTE FUNCTION kapit_revocation_guard();
"""


def install_guards(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        raise RuntimeError("KAPIT M1 requires PostgreSQL; no SQLite fallback is supported.")
    # SQL contains PostgreSQL format('%I'), not a driver parameter placeholder.
    schema_editor.execute(SQL, params=None)


def remove_guards(apps, schema_editor):
    # Only a reviewed migration rollback calls this; no application endpoint can.
    for function in ["kapit_publication_guard", "kapit_decision_guard", "kapit_revocation_guard", "kapit_source_link_guard", "kapit_variant_state_guard", "kapit_frozen_guard", "kapit_org_guard"]:
        schema_editor.execute(f"DROP FUNCTION IF EXISTS {function}() CASCADE")


class Migration(migrations.Migration):
    dependencies = [("operations", "0001_initial"), ("publications", "0001_initial"), ("audit", "0001_initial")]
    operations = [migrations.RunPython(install_guards, remove_guards)]
