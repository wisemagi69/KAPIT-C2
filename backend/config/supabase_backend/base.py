from django.db.backends.postgresql.base import DatabaseWrapper as PostgreSQLWrapper
from django.db.backends.postgresql.creation import DatabaseCreation as PostgreSQLCreation
from django.db.backends.postgresql.operations import DatabaseOperations as PostgreSQLOperations

from config.supabase import refuse_destructive_operation


class Creation(PostgreSQLCreation):
    def create_test_db(self, *args, **kwargs):
        refuse_destructive_operation()

    def _create_test_db(self, *args, **kwargs):
        refuse_destructive_operation()

    def destroy_test_db(self, *args, **kwargs):
        refuse_destructive_operation()

    def _destroy_test_db(self, *args, **kwargs):
        refuse_destructive_operation()

    def clone_test_db(self, *args, **kwargs):
        refuse_destructive_operation()

    def _clone_test_db(self, *args, **kwargs):
        refuse_destructive_operation()


class Operations(PostgreSQLOperations):
    def sql_flush(self, *args, **kwargs):
        refuse_destructive_operation()


class DatabaseWrapper(PostgreSQLWrapper):
    creation_class = Creation
    ops_class = Operations
