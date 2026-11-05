"""TASK-122 (M3): epoch, authority, integration-client and context-aware decision/publication guards.

Contract: docs/m3-implementation-plan.md §3.3 item 7 and §3.4; TASK-120 (contracts/m3). Additive only:
new functions and triggers, and CREATE OR REPLACE of three 0002 guard functions. NULL-context rows keep
the exact M1 checks plus epoch equality (and withdrawal refusal). The receipt and revision branches of
kapit_source_link_guard are taken verbatim from the 0002 source text (S8d), not retyped. Reverse SQL
restores the three 0002 function bodies verbatim from the same source.
"""
import importlib
import re

from django.db import migrations

ORIGINAL = importlib.import_module("apps.operations.migrations.0002_integrity_guards").SQL


def original_function(name):
    match = re.search(r"CREATE FUNCTION " + name + r"\(\).*?END \$\$;\n", ORIGINAL, re.S)
    if match is None:
        raise RuntimeError("0002 guard source not found: " + name)
    return match.group(0)


LEGACY_VARIANT_BRANCH = """  ELSIF TG_TABLE_NAME = 'reports_reportvariant' THEN
    SELECT * INTO job FROM operations_processingjob WHERE id = NEW.job_id;
    IF NEW.revision_id <> job.revision_id OR NEW.policy_id <> job.policy_id OR NEW.channel_ids <> job.channel_ids OR NEW.profile <> 'DEMO-REDUCED'
       OR NEW.projection->>'profile' IS DISTINCT FROM NEW.profile OR jsonb_typeof(NEW.channel_ids) IS DISTINCT FROM 'array'
       OR jsonb_array_length(NEW.channel_ids) <> 1 OR NEW.candidate_hash !~ '^[a-f0-9]{64}$' THEN
      RAISE EXCEPTION 'candidate processing context is inconsistent' USING ERRCODE = '23514';
    END IF;
  END IF;"""

M3_VARIANT_BRANCH = """  ELSIF TG_TABLE_NAME = 'reports_reportvariant' THEN
    SELECT * INTO job FROM operations_processingjob WHERE id = NEW.job_id;
    IF job.scope_context_hash IS NULL THEN
      IF NEW.revision_id <> job.revision_id OR NEW.policy_id <> job.policy_id OR NEW.channel_ids <> job.channel_ids OR NEW.profile <> 'DEMO-REDUCED'
         OR NEW.projection->>'profile' IS DISTINCT FROM NEW.profile OR jsonb_typeof(NEW.channel_ids) IS DISTINCT FROM 'array'
         OR jsonb_array_length(NEW.channel_ids) <> 1 OR NEW.candidate_hash !~ '^[a-f0-9]{64}$'
         OR NEW.scope_context_hash IS NOT NULL THEN
        RAISE EXCEPTION 'candidate processing context is inconsistent' USING ERRCODE = '23514';
      END IF;
    ELSIF NEW.revision_id <> job.revision_id OR NEW.policy_id <> job.policy_id
       OR NEW.scope_context_hash IS DISTINCT FROM job.scope_context_hash
       OR NEW.profile NOT IN ('DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY')
       OR NEW.projection->>'profile' IS DISTINCT FROM NEW.profile OR jsonb_typeof(NEW.channel_ids) IS DISTINCT FROM 'array'
       OR jsonb_array_length(NEW.channel_ids) < 1
       OR NEW.channel_ids IS DISTINCT FROM kapit_context_channels(job.scope_context, NEW.profile)
       OR NEW.candidate_hash !~ '^[a-f0-9]{64}$' THEN
      RAISE EXCEPTION 'candidate processing context is inconsistent' USING ERRCODE = '23514';
    END IF;
  END IF;"""

SOURCE_LINK_M1 = original_function("kapit_source_link_guard")
if SOURCE_LINK_M1.count(LEGACY_VARIANT_BRANCH) != 1:
    raise RuntimeError("0002 variant branch text changed; refusing to build the M3 source-link guard")
SOURCE_LINK_M3 = SOURCE_LINK_M1.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1).replace(LEGACY_VARIANT_BRANCH, M3_VARIANT_BRANCH)

HELPERS = r"""
CREATE FUNCTION kapit_profile_rank(profile text) RETURNS integer LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE coalesce(profile, 'DEMO-REDUCED') WHEN 'DEMO-FULL' THEN 3 WHEN 'DEMO-REDUCED' THEN 2 WHEN 'DEMO-SUMMARY' THEN 1 END
$$;

-- SQL recomputation of apps.reports.scope_context.build_context (TASK-122 parity test, F13).
-- NULL means the legacy context (exactly one eligible source, both maxima NULL) or no eligible source.
CREATE FUNCTION kapit_scope_context(target uuid) RETURNS jsonb LANGUAGE sql STABLE AS $$
  WITH unit AS (
    SELECT u.id, u.organization_id, u.scope_epoch, o.policy_epoch
    FROM scopes_unit u JOIN scopes_organization o ON o.id = u.organization_id WHERE u.id = target
  ), src AS (
    SELECT cs.channel_id, sc.max_profile AS channel_max, cs.max_profile AS source_max
    FROM scopes_channelsource cs JOIN scopes_sharingchannel sc ON sc.id = cs.channel_id JOIN scopes_unit su ON su.id = cs.unit_id
    WHERE cs.unit_id = target AND cs.active AND sc.active AND su.active AND cs.organization_id = (SELECT organization_id FROM unit)
  )
  SELECT CASE
    WHEN (SELECT count(*) FROM src) = 0 THEN NULL
    WHEN (SELECT count(*) FROM src) = 1 AND (SELECT bool_and(channel_max IS NULL AND source_max IS NULL) FROM src) THEN NULL
    ELSE jsonb_build_object(
      'v', 1, 'unit_id', target::text,
      'policy_epoch', (SELECT policy_epoch FROM unit), 'scope_epoch', (SELECT scope_epoch FROM unit),
      'channels', (
        SELECT jsonb_agg(jsonb_build_object('id', s.channel_id::text, 'profiles', (
          SELECT jsonb_agg(p.name ORDER BY p.rank DESC) FROM (VALUES ('DEMO-FULL', 3), ('DEMO-REDUCED', 2), ('DEMO-SUMMARY', 1)) AS p(name, rank)
          WHERE p.rank <= least(kapit_profile_rank(s.channel_max), kapit_profile_rank(s.source_max))))
          ORDER BY s.channel_id::text COLLATE "C")
        FROM src s))
  END
$$;

CREATE FUNCTION kapit_context_channels(context jsonb, profile text) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(jsonb_agg(c->'id' ORDER BY c->>'id' COLLATE "C"), '[]'::jsonb)
  FROM jsonb_array_elements(context->'channels') c WHERE c->'profiles' ? profile
$$;

CREATE FUNCTION kapit_epoch_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'scopes_organization' THEN
    IF NEW.policy_epoch < OLD.policy_epoch OR NEW.policy_epoch > OLD.policy_epoch + 1 THEN
      RAISE EXCEPTION 'policy epoch may only advance by one' USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.scope_epoch < OLD.scope_epoch OR NEW.scope_epoch > OLD.scope_epoch + 1 THEN
    RAISE EXCEPTION 'scope epoch may only advance by one' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_has_authority(person uuid, org uuid, wanted text) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM accounts_user a JOIN scopes_adminauthority aa ON aa.user_id = a.id
                 WHERE a.id = person AND a.organization_id = org AND a.is_active AND a.role = 'administrator'
                 AND aa.organization_id = org AND aa.kind = wanted AND aa.active)
$$;

CREATE FUNCTION kapit_policy_activation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE p scopes_policyproposal%ROWTYPE; target scopes_policyversion%ROWTYPE; proposer accounts_user%ROWTYPE; o scopes_organization%ROWTYPE;
BEGIN
  SELECT * INTO p FROM scopes_policyproposal WHERE id = NEW.proposal_id;
  SELECT * INTO target FROM scopes_policyversion WHERE id = p.target_policy_id;
  SELECT * INTO proposer FROM accounts_user WHERE id = p.proposer_id;
  SELECT * INTO o FROM scopes_organization WHERE id = NEW.organization_id;
  IF NEW.activator_id = p.proposer_id OR p.organization_id <> NEW.organization_id
     OR NOT kapit_has_authority(NEW.activator_id, NEW.organization_id, 'POLICY')
     OR NOT kapit_has_authority(p.proposer_id, NEW.organization_id, 'POLICY')
     OR proposer.permission_version <> p.proposer_permission_version
     OR NEW.activated_at > p.expires_at OR CURRENT_TIMESTAMP > p.expires_at
     OR p.target_rules_hash IS DISTINCT FROM target.rules_hash
     OR o.active_policy_id IS DISTINCT FROM p.expected_active_policy_id OR NOT o.active THEN
    RAISE EXCEPTION 'policy activation is inconsistent' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_client_approval_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE q accounts_integrationclientrequest%ROWTYPE;
BEGIN
  SELECT * INTO q FROM accounts_integrationclientrequest WHERE id = NEW.request_id;
  IF NEW.approver_id = q.requester_id OR q.organization_id <> NEW.organization_id OR q.profile_ceiling <> 'DEMO-FULL'
     OR NOT kapit_has_authority(NEW.approver_id, NEW.organization_id, 'INTEGRATION')
     OR NOT kapit_has_authority(q.requester_id, NEW.organization_id, 'INTEGRATION')
     OR NEW.approved_at > q.collect_deadline THEN
    RAISE EXCEPTION 'integration approval is inconsistent' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_client_issue_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE q accounts_integrationclientrequest%ROWTYPE; ch scopes_sharingchannel%ROWTYPE; approval accounts_integrationclientapproval%ROWTYPE;
BEGIN
  SELECT * INTO q FROM accounts_integrationclientrequest WHERE id = NEW.request_id;
  SELECT * INTO ch FROM scopes_sharingchannel WHERE id = NEW.channel_id;
  SELECT * INTO approval FROM accounts_integrationclientapproval WHERE request_id = NEW.request_id;
  IF NEW.channel_id <> q.channel_id OR NEW.profile_ceiling <> q.profile_ceiling OR NEW.label <> q.label
     OR NEW.organization_id <> q.organization_id OR NOT ch.active
     OR kapit_profile_rank(NEW.profile_ceiling) > kapit_profile_rank(ch.max_profile)
     OR NEW.created_at > q.collect_deadline OR NEW.created_at >= q.expires_at OR NEW.expires_at > q.expires_at
     OR NEW.revoked_at IS NOT NULL OR NEW.revoked_by_id IS NOT NULL
     OR NOT kapit_has_authority(q.requester_id, NEW.organization_id, 'INTEGRATION')
     OR (NEW.profile_ceiling = 'DEMO-FULL' AND (approval.id IS NULL OR NOT kapit_has_authority(approval.approver_id, NEW.organization_id, 'INTEGRATION'))) THEN
    RAISE EXCEPTION 'integration client issue is inconsistent' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION kapit_client_revocation_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS DISTINCT FROM OLD.revoked_at OR NEW.revoked_by_id IS DISTINCT FROM OLD.revoked_by_id) THEN
    RAISE EXCEPTION 'a revoked integration client cannot be reactivated' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
"""

DECISION_M3 = r"""
CREATE OR REPLACE FUNCTION kapit_decision_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v reports_reportvariant%ROWTYPE; r reports_reportrevision%ROWTYPE; source reports_report%ROWTYPE; actor accounts_user%ROWTYPE; p scopes_policyversion%ROWTYPE; channels jsonb;
        job operations_processingjob%ROWTYPE; o scopes_organization%ROWTYPE; unit scopes_unit%ROWTYPE; b review_decisionbatch%ROWTYPE;
BEGIN
  SELECT * INTO v FROM reports_reportvariant WHERE id = NEW.variant_id;
  SELECT * INTO r FROM reports_reportrevision WHERE id = v.revision_id;
  SELECT * INTO source FROM reports_report WHERE id = r.report_id;
  SELECT * INTO actor FROM accounts_user WHERE id = NEW.reviewer_id;
  SELECT * INTO p FROM scopes_policyversion WHERE id = v.policy_id;
  SELECT * INTO job FROM operations_processingjob WHERE id = v.job_id;
  SELECT * INTO o FROM scopes_organization WHERE id = NEW.organization_id;
  SELECT * INTO unit FROM scopes_unit WHERE id = source.unit_id;
  SELECT coalesce(jsonb_agg(cs.channel_id::text ORDER BY cs.channel_id), '[]'::jsonb) INTO channels
    FROM scopes_channelsource cs JOIN scopes_sharingchannel sc ON sc.id = cs.channel_id JOIN scopes_unit u ON u.id = cs.unit_id
    WHERE cs.unit_id = source.unit_id AND cs.active AND sc.active AND u.active AND cs.organization_id = NEW.organization_id;
  -- Checks shared by both contexts (the M1 reviewer, binding and current-policy rules), plus both epochs.
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
     OR NOT EXISTS (SELECT 1 FROM scopes_organization oo WHERE oo.id = NEW.organization_id AND oo.active AND oo.active_policy_id = p.id)
     OR job.policy_epoch <> o.policy_epoch OR job.scope_epoch <> unit.scope_epoch
     OR (NEW.action = 'APPROVE' AND EXISTS (SELECT 1 FROM publications_revisionwithdrawal w WHERE w.revision_id = r.id)) THEN
    RAISE EXCEPTION 'review decision is inconsistent' USING ERRCODE = '23514';
  END IF;
  IF v.scope_context_hash IS NULL THEN
    -- Legacy NULL context: the exact M1 single-channel rule.
    IF job.scope_context_hash IS NOT NULL OR v.channel_ids IS DISTINCT FROM channels OR jsonb_array_length(channels) <> 1 THEN
      RAISE EXCEPTION 'review decision is inconsistent' USING ERRCODE = '23514';
    END IF;
  ELSE
    SELECT * INTO b FROM review_decisionbatch WHERE id = NEW.batch_id;
    IF NEW.batch_id IS NULL OR b.revision_id <> r.id OR b.reviewer_id <> NEW.reviewer_id OR b.organization_id <> NEW.organization_id
       OR b.action <> NEW.action
       OR v.scope_context_hash IS DISTINCT FROM job.scope_context_hash
       OR NEW.binding->>'scope_context_hash' IS DISTINCT FROM v.scope_context_hash
       OR v.profile NOT IN ('DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY') OR v.projection->>'profile' IS DISTINCT FROM v.profile
       OR v.channel_ids IS DISTINCT FROM kapit_context_channels(job.scope_context, v.profile)
       OR job.scope_context IS DISTINCT FROM kapit_scope_context(source.unit_id) THEN
      RAISE EXCEPTION 'review decision is inconsistent' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;
"""

PUBLICATION_M3 = r"""
CREATE OR REPLACE FUNCTION kapit_publication_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v reports_reportvariant%ROWTYPE; d review_reviewdecision%ROWTYPE; r reports_reportrevision%ROWTYPE; p scopes_policyversion%ROWTYPE; source reports_report%ROWTYPE;
        job operations_processingjob%ROWTYPE; o scopes_organization%ROWTYPE; unit scopes_unit%ROWTYPE;
BEGIN
  SELECT * INTO v FROM reports_reportvariant WHERE id = NEW.variant_id;
  SELECT * INTO d FROM review_reviewdecision WHERE id = NEW.decision_id;
  SELECT * INTO r FROM reports_reportrevision WHERE id = v.revision_id;
  SELECT * INTO p FROM scopes_policyversion WHERE id = v.policy_id;
  SELECT * INTO source FROM reports_report WHERE id = r.report_id;
  SELECT * INTO job FROM operations_processingjob WHERE id = v.job_id;
  SELECT * INTO o FROM scopes_organization WHERE id = NEW.organization_id;
  SELECT * INTO unit FROM scopes_unit WHERE id = source.unit_id;
  IF d.variant_id <> v.id OR d.action <> 'APPROVE' OR v.state <> 'APPROVED'
     OR NEW.report_id <> r.report_id OR NEW.profile <> v.profile OR NEW.projection <> v.projection
     OR NOT (v.channel_ids @> jsonb_build_array(NEW.channel_id::text))
     OR d.binding->>'candidate_hash' IS DISTINCT FROM v.candidate_hash OR d.binding->'channel_ids' IS DISTINCT FROM v.channel_ids
     OR d.binding->>'revision_id' IS DISTINCT FROM r.id::text OR (d.binding->>'revision_no')::integer IS DISTINCT FROM r.revision_no
     OR d.binding->>'policy_version' IS DISTINCT FROM p.version OR d.binding->>'policy_hash' IS DISTINCT FROM p.rules_hash
     OR NOT p.active OR r.revision_no <> source.current_revision_no
     OR NOT EXISTS (SELECT 1 FROM scopes_organization oo WHERE oo.id = NEW.organization_id AND oo.active AND oo.active_policy_id = p.id)
     OR NOT EXISTS (SELECT 1 FROM scopes_channelsource c JOIN scopes_sharingchannel sc ON sc.id = c.channel_id JOIN scopes_unit u ON u.id = c.unit_id
                    WHERE c.channel_id = NEW.channel_id AND c.unit_id = source.unit_id AND c.active AND sc.active AND u.active)
     OR job.policy_epoch <> o.policy_epoch OR job.scope_epoch <> unit.scope_epoch
     OR EXISTS (SELECT 1 FROM publications_revisionwithdrawal w WHERE w.revision_id = r.id) THEN
    RAISE EXCEPTION 'publication is inconsistent' USING ERRCODE = '23514';
  END IF;
  IF v.scope_context_hash IS NOT NULL AND (
       v.scope_context_hash IS DISTINCT FROM job.scope_context_hash
       OR d.binding->>'scope_context_hash' IS DISTINCT FROM v.scope_context_hash OR d.batch_id IS NULL
       OR NEW.profile NOT IN ('DEMO-FULL', 'DEMO-REDUCED', 'DEMO-SUMMARY')
       OR job.scope_context IS DISTINCT FROM kapit_scope_context(source.unit_id)) THEN
    RAISE EXCEPTION 'publication is inconsistent' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
"""

TRIGGERS = r"""
CREATE TRIGGER e_epoch_guard BEFORE UPDATE ON scopes_organization FOR EACH ROW EXECUTE FUNCTION kapit_epoch_guard();
CREATE TRIGGER e_epoch_guard BEFORE UPDATE ON scopes_unit FOR EACH ROW EXECUTE FUNCTION kapit_epoch_guard();

CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_adminauthority FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('user_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_policyproposal FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('target_policy_id','scopes_policyversion','proposer_id','accounts_user','expected_active_policy_id','scopes_policyversion');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON scopes_policyactivation FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('proposal_id','scopes_policyproposal','activator_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON accounts_integrationclientrequest FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('requester_id','accounts_user','channel_id','scopes_sharingchannel');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON accounts_integrationclientapproval FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('request_id','accounts_integrationclientrequest','approver_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON accounts_integrationclient FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('request_id','accounts_integrationclientrequest','channel_id','scopes_sharingchannel','revoked_by_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON review_decisionbatch FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('reviewer_id','accounts_user','revision_id','reports_reportrevision');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON publications_revisionwithdrawal FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('revision_id','reports_reportrevision','report_id','reports_report','reviewer_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON publications_publicationremoval FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('publication_id','publications_publication','actor_id','accounts_user');
CREATE TRIGGER a_org_guard BEFORE INSERT OR UPDATE ON publications_publicationdelivery FOR EACH ROW EXECUTE FUNCTION kapit_org_guard('publication_id','publications_publication','user_id','accounts_user','client_id','accounts_integrationclient','channel_id','scopes_sharingchannel');

CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON scopes_adminauthority FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard('active');
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON scopes_policyproposal FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON scopes_policyactivation FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON accounts_integrationclientrequest FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON accounts_integrationclientapproval FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON accounts_integrationclient FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard('revoked_at','revoked_by_id');
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON review_decisionbatch FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON publications_revisionwithdrawal FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON publications_publicationremoval FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();
CREATE TRIGGER b_frozen_guard BEFORE UPDATE OR DELETE ON publications_publicationdelivery FOR EACH ROW EXECUTE FUNCTION kapit_frozen_guard();

CREATE TRIGGER c_policy_activation BEFORE INSERT ON scopes_policyactivation FOR EACH ROW EXECUTE FUNCTION kapit_policy_activation_guard();
CREATE TRIGGER c_client_approval BEFORE INSERT ON accounts_integrationclientapproval FOR EACH ROW EXECUTE FUNCTION kapit_client_approval_guard();
CREATE TRIGGER c_client_issue BEFORE INSERT ON accounts_integrationclient FOR EACH ROW EXECUTE FUNCTION kapit_client_issue_guard();
CREATE TRIGGER c_client_revocation BEFORE UPDATE ON accounts_integrationclient FOR EACH ROW EXECUTE FUNCTION kapit_client_revocation_guard();
"""

NEW_FUNCTIONS = ["kapit_client_revocation_guard", "kapit_client_issue_guard", "kapit_client_approval_guard", "kapit_policy_activation_guard",
                 "kapit_epoch_guard"]
NEW_TRIGGERS = [("e_epoch_guard", "scopes_organization"), ("e_epoch_guard", "scopes_unit")]
NEW_TABLE_TRIGGERS = ["scopes_adminauthority", "scopes_policyproposal", "scopes_policyactivation", "accounts_integrationclientrequest",
                      "accounts_integrationclientapproval", "accounts_integrationclient", "review_decisionbatch",
                      "publications_revisionwithdrawal", "publications_publicationremoval", "publications_publicationdelivery"]


def install(apps, schema_editor):
    if schema_editor.connection.vendor != "postgresql":
        raise RuntimeError("KAPIT M3 guards require PostgreSQL; no SQLite fallback is supported.")
    # SQL contains PostgreSQL format('%I') and jsonb '?' operators, not driver placeholders.
    schema_editor.execute(HELPERS, params=None)
    schema_editor.execute(SOURCE_LINK_M3, params=None)
    schema_editor.execute(DECISION_M3, params=None)
    schema_editor.execute(PUBLICATION_M3, params=None)
    schema_editor.execute(TRIGGERS, params=None)


def restore(apps, schema_editor):
    # Restore the three 0002 bodies verbatim, then remove only what this migration added.
    for name in ("kapit_source_link_guard", "kapit_decision_guard", "kapit_publication_guard"):
        schema_editor.execute(original_function(name).replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION", 1), params=None)
    for trigger, table in NEW_TRIGGERS:
        schema_editor.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {table}")
    for table in NEW_TABLE_TRIGGERS:
        for trigger in ("a_org_guard", "b_frozen_guard", "c_policy_activation", "c_client_approval", "c_client_issue", "c_client_revocation"):
            schema_editor.execute(f"DROP TRIGGER IF EXISTS {trigger} ON {table}")
    for function in NEW_FUNCTIONS:
        schema_editor.execute(f"DROP FUNCTION IF EXISTS {function}()")
    schema_editor.execute("DROP FUNCTION IF EXISTS kapit_has_authority(uuid, uuid, text)")
    schema_editor.execute("DROP FUNCTION IF EXISTS kapit_context_channels(jsonb, text)")
    schema_editor.execute("DROP FUNCTION IF EXISTS kapit_scope_context(uuid)")
    schema_editor.execute("DROP FUNCTION IF EXISTS kapit_profile_rank(text)")


class Migration(migrations.Migration):
    dependencies = [
        ("operations", "0004_m3_scope_context"),
        ("scopes", "0004_m3_scope_profiles"),
        ("accounts", "0004_m3_integration_clients"),
        ("reports", "0004_m3_variants_corrections"),
        ("review", "0002_m3_decision_batch"),
        ("publications", "0002_m3_lifecycle"),
    ]
    operations = [migrations.RunPython(install, restore)]
