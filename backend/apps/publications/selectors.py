"""One current authorized publication dataset for recipient lists, maps and clients."""
from collections import Counter
from dataclasses import dataclass

from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone

from apps.accounts.models import IntegrationClient
from apps.operations.errors import ApiError, missing
from apps.operations.pagination import pagination_values, query_values
from apps.operations.worker import binding_for, candidate_digest
from apps.reports.crypto import digest
from apps.reports.projection import POLICIES, PROFILE_KEYS, PROFILE_RANK, served_published_at, valid_projection
from apps.reports.regeneration import job_is_current
from apps.scopes.access import lock_identity, recipient_grant, require_role
from apps.scopes.models import ChannelMember

from .models import Publication, PublicationDelivery, PublicationRemoval, RevisionWithdrawal
from .delivery import record_deliveries


@dataclass(frozen=True)
class RecipientScope:
    channel: object
    ceiling: str
    expanded: bool
    client: object = None


def supported_policy(org):
    policy = org.active_policy
    return (org.active and policy is not None and policy.active and policy.organization_id == org.id
            and policy.version in POLICIES and policy.rules == POLICIES[policy.version]
            and digest(policy.rules) == policy.rules_hash)


def recipient_scope(actor, org, channel_id, *, client=None):
    """Client is an authenticated capability, never a request-supplied UUID."""
    if client is not None:
        if actor is not None:
            raise missing()
        current = IntegrationClient.objects.filter(pk=client.pk, organization=org, channel_id=channel_id,
            channel__organization=org, channel__active=True, revoked_at__isnull=True,
            expires_at__gt=timezone.now(), profile_ceiling__in=PROFILE_RANK).select_related("channel").first()
        if current is None or not org.active:
            raise missing()
        maximum = current.channel.max_profile or "DEMO-REDUCED"
        if maximum not in PROFILE_RANK or PROFILE_RANK[current.profile_ceiling] > PROFILE_RANK[maximum]:
            raise missing()
        return RecipientScope(current.channel, current.profile_ceiling, True, current)
    require_role(actor, "recipient")
    if actor.organization_id != org.id or not actor.is_active or not org.active:
        raise missing()
    grant = recipient_grant(actor, channel_id)
    maximum = grant.channel.max_profile or "DEMO-REDUCED"
    if maximum not in PROFILE_RANK:
        raise missing()
    ceiling = min((grant.profile_ceiling, maximum), key=PROFILE_RANK.get)
    return RecipientScope(grant.channel, ceiling,
        grant.profile_ceiling != "DEMO-REDUCED" or grant.channel.max_profile is not None)


def current_dataset(actor, org, *, client=None):
    if client is None:
        require_role(actor, "recipient")
        grants = ChannelMember.objects.filter(user_id=actor.pk, organization=org, channel__organization=org,
            channel__active=True, active=True, revoked_at__isnull=True, profile_ceiling__in=PROFILE_RANK).filter(
                Q(valid_until__isnull=True) | Q(valid_until__gt=timezone.now())).order_by("channel_id")
        scopes = []
        for grant in grants:
            try:
                scopes.append(recipient_scope(actor, org, grant.channel_id))
            except ApiError as error:
                if error.status_code != 404:
                    raise
    else:
        scopes = [recipient_scope(None, org, client.channel_id, client=client)]
    if not supported_policy(org):
        return Publication.objects.none()
    permitted = Q(pk__isnull=True)
    for scope in scopes:
        profiles = [name for name, rank in PROFILE_RANK.items() if rank <= PROFILE_RANK[scope.ceiling]]
        permitted |= Q(channel_id=scope.channel.id, profile__in=profiles)
    return Publication.objects.filter(permitted, organization=org, revoked_at__isnull=True,
        report__organization=org, report__unit__active=True, variant__organization=org,
        variant__policy_id=org.active_policy_id, variant__state="APPROVED", decision__action="APPROVE",
        decision__organization=org, variant__revision__revision_no=F("report__current_revision_no"),
        removal__isnull=True).select_related("channel", "report__unit", "variant__revision__report__unit",
            "variant__policy", "variant__job", "decision__batch").order_by("-published_at", "-id")


def current_publications(actor, org, channel_id, *, client=None):
    scope = recipient_scope(actor, org, channel_id, client=client)
    return scope, current_dataset(actor, org, client=client).filter(channel_id=channel_id)


def valid_publication(publication, org):
    """Current validity only; every caller also enforces live action/channel/ceiling."""
    try:
        return _valid_publication(publication, org)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def _valid_publication(publication, org):
    variant, decision, report = publication.variant, publication.decision, publication.report
    revision, job, policy = variant.revision, variant.job, org.active_policy
    if (not supported_policy(org) or publication.organization_id != org.id or report.organization_id != org.id
            or report.unit.organization_id != org.id or not report.unit.active
            or publication.channel.organization_id != org.id or not publication.channel.active
            or publication.revoked_at is not None or publication.profile not in PROFILE_RANK
            or variant.organization_id != org.id or variant.policy_id != policy.id or variant.state != "APPROVED"
            or variant.profile != publication.profile or revision.organization_id != org.id
            or revision.processing_state != "AWAITING_REVIEW" or job.status != "DONE"
            or job.revision_id != revision.id or job.policy_id != variant.policy_id or job.organization_id != org.id
            or decision.organization_id != org.id or decision.action != "APPROVE"
            or publication.report_id != revision.report_id or decision.variant_id != variant.id
            or publication.projection != variant.projection or decision.binding != binding_for(variant)):
        return False
    if PublicationRemoval.objects.filter(organization=org, publication=publication).exists():
        return False
    if RevisionWithdrawal.objects.filter(organization=org, revision=revision).exists() or not job_is_current(job, org):
        return False
    if job.scope_context is None:
        if variant.scope_context_hash is not None or variant.profile != "DEMO-REDUCED" or variant.channel_ids != job.channel_ids or len(job.channel_ids) != 1:
            return False
    else:
        if (digest(job.scope_context) != job.scope_context_hash or variant.scope_context_hash != job.scope_context_hash
                or decision.batch_id is None or decision.batch.revision_id != revision.id
                or decision.batch.organization_id != org.id or decision.batch.reviewer_id != decision.reviewer_id
                or decision.batch.action != "APPROVE"):
            return False
        channels = [row["id"] for row in job.scope_context["channels"] if variant.profile in row["profiles"]]
        if variant.channel_ids != channels:
            return False
    if str(publication.channel_id) not in variant.channel_ids:
        return False
    unit = {"code": report.unit.code, "name": report.unit.name} if variant.profile == "DEMO-FULL" else None
    if not valid_projection(publication.projection, variant.profile, unit, policy.rules):
        return False
    return candidate_digest(variant.projection, revision.id, revision.revision_no, revision.content_digest,
        policy.id, policy.rules_hash, variant.profile, variant.channel_ids, scope_context_hash=job.scope_context_hash,
        policy_epoch=job.policy_epoch, scope_epoch=job.scope_epoch) == variant.candidate_hash


def selected_publications(actor, org, channel_id, profile=None, *, client=None):
    """Scope → validity → ceiling → highest/report, before any content filter."""
    scope, dataset = current_publications(actor, org, channel_id, client=client)
    ceiling = scope.ceiling if profile is None else profile
    if (not isinstance(ceiling, str) or ceiling not in PROFILE_RANK
            or PROFILE_RANK[ceiling] > PROFILE_RANK[scope.ceiling]):
        raise ApiError("INVALID_FILTER", "Choose a supported profile within your current ceiling.")
    selected = {}
    for publication in dataset.iterator(chunk_size=100):
        if not valid_publication(publication, org) or PROFILE_RANK[publication.profile] > PROFILE_RANK[ceiling]:
            continue
        key = (publication.report_id, publication.channel_id)
        previous = selected.get(key)
        if previous is None or PROFILE_RANK[publication.profile] > PROFILE_RANK[previous.profile]:
            selected[key] = publication
    return scope, sorted(selected.values(), key=lambda value: (value.published_at, value.id), reverse=True)


def serialize_publication(publication):
    profile = publication.profile
    return {"id": str(publication.id), "published_at": served_published_at(publication.published_at, profile),
            "channel": {"id": str(publication.channel.id), "code": publication.channel.code, "name": publication.channel.name},
            "projection": {key: publication.projection[key] for key in PROFILE_KEYS[profile]}}


def feed_filters(params):
    values = query_values(params, {"q", "category", "urgency", "area", "profile", "page", "page_size"})
    result = pagination_values(values)
    result.update(q=values.get("q", "").strip(), category=values.get("category", "ALL"),
                  urgency=values.get("urgency", "ALL"), area=values.get("area", "ALL"))
    if (len(result["q"]) > 120 or result["category"] not in {"ALL", "INFRASTRUCTURE", "WATER_SUPPLY", "EQUIPMENT"}
            or result["urgency"] not in {"ALL", "ROUTINE", "PRIORITY"} or result["area"] not in {"ALL", "Area A", "Area B", "Area C"}):
        raise ApiError("INVALID_FILTER", "Use supported publication filters and a search of at most 120 characters.")
    if "profile" in values:
        if values["profile"] not in PROFILE_RANK:
            raise ApiError("INVALID_FILTER", "Choose a supported disclosure profile.")
        result["profile"] = values["profile"]
    return result


def matches_projection(projection, options):
    if options["category"] != "ALL" and projection["category"] != options["category"]:
        return False
    if options["urgency"] != "ALL" and projection["urgency"] != options["urgency"]:
        return False
    if options.get("area", "ALL") != "ALL" and projection.get("area_label") != options["area"]:
        return False
    text = " ".join(projection[field] for field in ("title", "text", "area_label", "assistance_requested") if field in projection)
    return options["q"].casefold() in text.casefold()


def filtered_publications(scope, selected, options):
    effective = options.get("profile", scope.ceiling)
    if effective == "DEMO-SUMMARY" and options.get("area", "ALL") != "ALL":
        raise ApiError("INVALID_FILTER", "Area filters are unavailable for this profile.")
    return [value for value in selected if matches_projection(value.projection, options)]


def summarize(values):
    return {"by_category": dict(Counter(value.projection["category"] for value in values)),
            "by_urgency": dict(Counter(value.projection["urgency"] for value in values)),
            "by_area": dict(Counter(value.projection["area_label"] for value in values if "area_label" in value.projection)),
            "unmapped": sum("area_label" not in value.projection for value in values)}


def _read_identity(actor, org):
    current, locked_org = lock_identity(actor)
    if locked_org.id != org.id:
        raise missing()
    return current, locked_org


@transaction.atomic
def feed(actor, org, channel_id, params=None):
    actor, org = _read_identity(actor, org)
    recipient_scope(actor, org, channel_id)  # live action/scope denial precedes filter diagnostics
    options = feed_filters(params) if params is not None else {"q": "", "category": "ALL", "urgency": "ALL", "area": "ALL", "page": 1, "page_size": 10}
    scope, chosen = selected_publications(actor, org, channel_id, options.get("profile"))
    values = filtered_publications(scope, chosen, options)
    page, size, count = options["page"], options["page_size"], len(values)
    visible = values[(page - 1) * size:page * size]
    record_deliveries(actor, org, visible)
    result = {"results": [serialize_publication(value) for value in visible], "count": count,
              "page": page, "page_size": size, "total_pages": max(1, (count + size - 1) // size)}
    if scope.expanded or "profile" in options or options.get("area", "ALL") != "ALL":
        result.update(profile=options.get("profile", scope.ceiling), summary=summarize(values))
    return result


@transaction.atomic
def detail(actor, org, publication_id):
    actor, org = _read_identity(actor, org)
    target = current_dataset(actor, org).filter(pk=publication_id).first()
    if target is None:
        raise missing()
    scope = recipient_scope(actor, org, target.channel_id)
    if target.profile not in PROFILE_RANK or PROFILE_RANK[target.profile] > PROFILE_RANK[scope.ceiling]:
        raise missing()
    _, selected = selected_publications(actor, org, target.channel_id, target.profile)
    if not any(value.id == target.id for value in selected):
        raise missing()
    record_deliveries(actor, org, [target])
    return serialize_publication(target)


@transaction.atomic
def map_counts(actor, org, channel_id, params):
    actor, org = _read_identity(actor, org)
    recipient_scope(actor, org, channel_id)
    options = feed_filters(params)
    scope, chosen = selected_publications(actor, org, channel_id, options.get("profile"))
    values = filtered_publications(scope, chosen, options)
    summary = summarize(values)
    anchors = {"Area A": "area-a", "Area B": "area-b", "Area C": "area-c"}
    return {"areas": [{"area_id": anchors[area], "count": count} for area, count in sorted(summary["by_area"].items())],
            "unmapped": summary["unmapped"]}


def removed_for_scope(actor, org, scope):
    principal = {"user": actor, "client__isnull": True} if scope.client is None else {"client": scope.client, "user__isnull": True}
    ledger = PublicationDelivery.objects.filter(organization=org, channel=scope.channel, **principal).select_related(
        "publication__channel", "publication__report__unit", "publication__variant__revision__report__unit",
        "publication__variant__policy", "publication__variant__job", "publication__decision__batch").order_by("publication_id")
    result = []
    for delivered in ledger.iterator(chunk_size=100):
        publication = delivered.publication
        if (publication.organization_id != org.id or publication.channel_id != scope.channel.id
                or delivered.profile != publication.profile or publication.profile not in PROFILE_RANK
                or PROFILE_RANK[publication.profile] > PROFILE_RANK[scope.ceiling]):
            continue
        # A still-valid explicitly requested lower profile is not instantly removed.
        if not valid_publication(publication, org):
            result.append({"publication_id": str(publication.id), "state": "WITHDRAWN"})
    return {"results": result}


@transaction.atomic
def removed(actor, org, channel_id):
    actor, org = _read_identity(actor, org)
    return removed_for_scope(actor, org, recipient_scope(actor, org, channel_id))
