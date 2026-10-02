"""Single place that knows where credentials come from (env locally, secret scope on Databricks)."""
import os


def on_databricks():
    return bool(os.getenv("DATABRICKS_RUNTIME_VERSION"))


def get_secret(name, *, scope=None, env_var=None, required=True):
    if on_databricks() and scope:
        try:
            from databricks.sdk import WorkspaceClient

            return WorkspaceClient().dbutils.secrets.get(scope=scope, key=name)
        except Exception:
            if required:
                raise
            return None
    value = os.getenv(env_var or name.upper().replace("-", "_"))
    if value:
        return value
    if required:
        raise RuntimeError("Missing secret %r (env %r)" % (name, env_var))
    return None
