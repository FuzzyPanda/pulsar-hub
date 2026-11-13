"""Make the audit table append-only in the database itself.

UPDATE is refused, except the one Django issues when a login is deleted (actor set to NULL, every
other column unchanged). DELETE is refused unless the transaction has set `hub.audit_purge`, which
only `delete_organisation` does.
"""

from django.db import migrations

CREATE = """
CREATE FUNCTION hub_audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.actor_id IS NULL
           AND (to_jsonb(NEW) - 'actor_id') = (to_jsonb(OLD) - 'actor_id') THEN
            RETURN NEW;
        END IF;
        RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = 'insufficient_privilege';
    END IF;
    IF current_setting('hub.audit_purge', true) = 'on' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER hub_audit_append_only
    BEFORE UPDATE OR DELETE ON audit_auditevent
    FOR EACH ROW EXECUTE FUNCTION hub_audit_append_only();
"""

DROP = """
DROP TRIGGER IF EXISTS hub_audit_append_only ON audit_auditevent;
DROP FUNCTION IF EXISTS hub_audit_append_only();
"""


class Migration(migrations.Migration):
    dependencies = [("audit", "0001_initial")]

    operations = [migrations.RunSQL(CREATE, DROP)]
