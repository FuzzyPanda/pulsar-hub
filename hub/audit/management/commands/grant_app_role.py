import environ
from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from psycopg import sql

# What the running service may do. Everything it needs for normal work, and on the audit table
# only INSERT and SELECT: history can be added to and read, never changed.
AUDIT_TABLE = "audit_auditevent"
PURGE_FUNCTION = "hub_purge_organisation_audit(uuid)"


class Command(BaseCommand):
    help = (
        "Create or update the database role the running service connects as, and set its rights. "
        "Run as the owning role (HUB_DATABASE_AS_OWNER=1) after every migrate; it is idempotent. "
        "The role's name and password are read from DATABASE_URL."
    )

    def handle(self, *args, **options):
        app = environ.Env().db("DATABASE_URL")
        role, password = app.get("USER"), app.get("PASSWORD")
        owner = connection.settings_dict["USER"]
        if not role or not password:
            raise CommandError("DATABASE_URL must name the application role and its password.")
        if role == owner:
            raise CommandError(
                "DATABASE_URL and DATABASE_OWNER_URL name the same role. Give the service its own role, "
                "or leave DATABASE_OWNER_URL unset to run with a single role (development only)."
            )
        ident = sql.Identifier(role)
        database = sql.Identifier(connection.settings_dict["NAME"])
        with connection.cursor() as cursor:  # unscoped: role and privilege statements; reads no business row
            # CREATE ROLE gives no special attributes by default. The dangerous ones (SUPERUSER,
            # REPLICATION, BYPASSRLS) are not named here because only a superuser may name them;
            # they are checked afterwards instead.
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", [role])
            verb = sql.SQL("ALTER ROLE") if cursor.fetchone() else sql.SQL("CREATE ROLE")
            cursor.execute(
                sql.SQL("{verb} {role} LOGIN NOCREATEDB NOCREATEROLE PASSWORD {pw}").format(
                    verb=verb, role=ident, pw=sql.Literal(password)
                )
            )
            cursor.execute(
                "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls"
                " FROM pg_roles WHERE rolname = %s",
                [role],
            )
            if cursor.fetchone()[0]:
                raise CommandError(f"Role {role} holds elevated attributes; it must be an ordinary login role.")
            for statement in (
                "GRANT CONNECT ON DATABASE {db} TO {role}",
                "GRANT USAGE ON SCHEMA public TO {role}",
                "REVOKE CREATE ON SCHEMA public FROM {role}",
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}",
                "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}",
                "REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON " + AUDIT_TABLE + " FROM {role}",
                "REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON django_migrations FROM {role}",
                "GRANT EXECUTE ON FUNCTION " + PURGE_FUNCTION + " TO {role}",
            ):
                cursor.execute(sql.SQL(statement).format(db=database, role=ident))
        self.stdout.write(f"Role {role}: rights set (audit table is insert and read only).")
