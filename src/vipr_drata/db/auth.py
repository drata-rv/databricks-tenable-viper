"""Databricks client: OAuth M2M first, PAT fallback. One secret scope per workspace."""
import os

from .secrets import get_secret


def scope_for(workspace):
    return os.getenv("DATABRICKS_SECRET_SCOPE_%s" % workspace.upper()) or os.getenv("DATABRICKS_SECRET_SCOPE")


def get_client_for_env(workspace):
    from databricks.sdk import WorkspaceClient

    ws = workspace.lower()
    up = workspace.upper()
    scope = scope_for(workspace)
    host = get_secret("databricks-host-" + ws, scope=scope, env_var="DATABRICKS_HOST_" + up)
    cid = get_secret("databricks-client-id-" + ws, scope=scope, env_var="DATABRICKS_CLIENT_ID_" + up, required=False)
    csec = get_secret("databricks-client-secret-" + ws, scope=scope, env_var="DATABRICKS_CLIENT_SECRET_" + up, required=False)
    if cid and csec:
        return WorkspaceClient(host=host, client_id=cid, client_secret=csec)
    token = get_secret("databricks-token-" + ws, scope=scope, env_var="DATABRICKS_TOKEN_" + up)
    return WorkspaceClient(host=host, token=token)


def drata_api_key(prod, workspace="test"):
    """Explicit sandbox/prod selection; prod never falls back to sandbox credentials.
    Scope is the running workspace's (the only one the job principal can read)."""
    scope = scope_for(workspace)
    if prod:
        return get_secret("drata-api-key-prod", scope=scope, env_var="DRATA_API_KEY_PROD")
    return get_secret("drata-api-key", scope=scope, env_var="DRATA_API_KEY")
