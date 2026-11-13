"""Make the audit table append-only in the database itself.

* UPDATE is always refused.
* DELETE is refused unless the row belongs to an organisation that is marked as being deleted.
  Events of a live organisation, and account-level and platform events, can never be removed.

`hub_purge_organisation_audit` is the one caller of that DELETE. It is SECURITY DEFINER so that the
application's own database role, which holds only INSERT and SELECT on this table (see
`manage.py grant_app_role`), can still delete an organisation.
"""

from django.db import migrations

CREATE = """
CREATE FUNCTION hub_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.organisation_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM organisations_organisation WHERE id = OLD.organisation_id AND status = 'deleting'
    ) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER hub_audit_append_only
    BEFORE UPDATE OR DELETE ON audit_auditevent
    FOR EACH ROW EXECUTE FUNCTION hub_audit_append_only();

CREATE FUNCTION hub_purge_organisation_audit(org uuid) RETURNS bigint
    LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    removed bigint;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM organisations_organisation WHERE id = org AND status = 'deleting') THEN
        RAISE EXCEPTION 'organisation % is not being deleted', org USING ERRCODE = 'insufficient_privilege';
    END IF;
    DELETE FROM audit_auditevent WHERE organisation_id = org;
    GET DIAGNOSTICS removed = ROW_COUNT;
    RETURN removed;
END;
$$;

REVOKE ALL ON FUNCTION hub_purge_organisation_audit(uuid) FROM PUBLIC;
"""

DROP = """
DROP FUNCTION IF EXISTS hub_purge_organisation_audit(uuid);
DROP TRIGGER IF EXISTS hub_audit_append_only ON audit_auditevent;
DROP FUNCTION IF EXISTS hub_audit_append_only();
"""


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial"), ("organisations", "0001_initial")]

    operations = [migrations.RunSQL(CREATE, DROP)]
