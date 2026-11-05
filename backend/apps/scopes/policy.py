"""Two-person synthetic policy transitions; callers never approve reports here."""
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone

from apps.audit import service as audit
from apps.operations.errors import ApiError, missing
from apps.reports.crypto import digest
from apps.reports.projection import POLICIES
from apps.reports.regeneration import invalidate_policy
from .access import lock_identity
from .authority import has_authority, require_authority
from .models import PolicyActivation, PolicyProposal, PolicyVersion


def stale():
    return ApiError("STALE_POLICY", "Reload the current policy state before continuing.", 409)


def supported(policy):
    return (policy.version in POLICIES and policy.rules == POLICIES[policy.version]
            and digest(policy.rules) == policy.rules_hash)


def proposal_body(row):
    return {"id": str(row.id), "kind": row.kind, "target_policy_id": str(row.target_policy_id),
            "target_rules_hash": row.target_rules_hash,
            "expected_active_policy_id": str(row.expected_active_policy_id) if row.expected_active_policy_id else None,
            "proposer_id": str(row.proposer_id), "proposed_at": row.proposed_at.isoformat(),
            "expires_at": row.expires_at.isoformat()}


def activation_body(row):
    return {"activation_id": str(row.id), "proposal_id": str(row.proposal_id),
            "kind": row.proposal.kind, "target_policy_id": str(row.proposal.target_policy_id),
            "activated_at": row.activated_at.isoformat()}


@transaction.atomic
def state(user):
    actor, org = lock_identity(user)
    require_authority(actor, "POLICY")
    policies = PolicyVersion.objects.filter(organization=org).order_by("version", "id")
    proposals = PolicyProposal.objects.filter(organization=org).select_related("policyactivation").order_by("-proposed_at", "-id")[:50]
    result = {"active_policy_id": str(org.active_policy_id) if org.active_policy_id else None,
              "policy_epoch": org.policy_epoch,
              "policies": [{"id": str(row.id), "version": row.version, "rules_hash": row.rules_hash,
                            "active": row.active, "supported": supported(row)} for row in policies],
              "proposals": [{**proposal_body(row), "applied": hasattr(row, "policyactivation")} for row in proposals]}
    return result


@transaction.atomic
def propose(user, data, raw_body):
    actor, org = lock_identity(user)
    require_authority(actor, "POLICY")
    request_hash = digest({"route": "POST /administration/policy/proposals/", "body": raw_body})
    prior = PolicyProposal.objects.filter(organization=org, proposer=actor, operation_id=data["operation_id"]).first()
    if prior:
        if prior.request_hash != request_hash:
            raise ApiError("IDEMPOTENCY_CONFLICT", "This operation already has a different request.", 409)
        return proposal_body(prior), False
    target = PolicyVersion.objects.select_for_update().filter(pk=data["target_policy_id"], organization=org).first()
    if target is None:
        raise missing()
    expected = data["expected_active_policy_id"]
    if ((str(org.active_policy_id) if org.active_policy_id else None) != (str(expected) if expected else None)
            or not supported(target) or target.rules_hash != data["target_rules_hash"]
            or (data["kind"] == "ACTIVATE" and target.id == org.active_policy_id)
            or (data["kind"] == "DEACTIVATE" and target.id != org.active_policy_id)):
        raise stale()
    now = timezone.now()
    row = PolicyProposal.objects.create(organization=org, kind=data["kind"], target_policy=target,
        target_rules_hash=target.rules_hash, expected_active_policy_id=org.active_policy_id,
        proposer=actor, proposer_permission_version=actor.permission_version, operation_id=data["operation_id"],
        request_hash=request_hash, proposed_at=now, expires_at=now + timedelta(hours=24))
    audit.record(org.id, actor, "POLICY_PROPOSED", row.id, operation_id=str(data["operation_id"]))
    return proposal_body(row), True


@transaction.atomic
def apply(user, proposal_id):
    actor, org = lock_identity(user)
    require_authority(actor, "POLICY")
    row = PolicyProposal.objects.select_for_update().filter(pk=proposal_id, organization=org).select_related("target_policy").first()
    if row is None:
        raise missing()
    if row.proposer_id == actor.id:
        raise ApiError("SELF_APPROVAL_DENIED", "A different policy authority holder must apply this proposal.", 403)
    proposer = get_user_model().objects.select_for_update().filter(pk=row.proposer_id, organization=org).first()
    if proposer is None or not has_authority(proposer, "POLICY") or proposer.permission_version != row.proposer_permission_version:
        raise stale()
    prior = PolicyActivation.objects.filter(organization=org, proposal=row).select_related("proposal").first()
    if prior:
        if prior.activator_id != actor.id:
            raise stale()
        # Historical replay cannot reactivate a pointer, increase an epoch or queue work.
        return activation_body(prior), False
    target = PolicyVersion.objects.select_for_update().get(pk=row.target_policy_id, organization=org)
    now = timezone.now()
    if (now >= row.expires_at or org.active_policy_id != row.expected_active_policy_id
            or PolicyActivation.objects.filter(organization=org, activated_at__gte=row.proposed_at).exists()
            or target.rules_hash != row.target_rules_hash or not supported(target)
            or (row.kind == "ACTIVATE" and target.id == org.active_policy_id)
            or (row.kind == "DEACTIVATE" and target.id != org.active_policy_id)):
        raise stale()
    # The insert trigger rechecks the OLD pointer and both authorities, before effects.
    activation = PolicyActivation.objects.create(organization=org, proposal=row, activator=actor, activated_at=now)
    PolicyVersion.objects.filter(organization=org, active=True).update(active=False)
    if row.kind == "ACTIVATE":
        target.active = True
        target.save(update_fields=["active"])
        org.active_policy = target
    else:
        org.active_policy = None
    org.save(update_fields=["active_policy"])
    invalidate_policy(org, actor=actor)
    return activation_body(activation), True
