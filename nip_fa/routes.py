"""Adapter route paths, shared by the router and the configured public URLs."""

ROUTE_PREFIX = "/nip-fa"
ASSERTIONS_ROUTE = "/v1/identity/assertions"
ASSERTIONS_PATH = ROUTE_PREFIX + ASSERTIONS_ROUTE
AGENT_GRANT_ROUTE = "/v1/nip-fi/agent-grant"
AGENT_GRANT_PATH = ROUTE_PREFIX + AGENT_GRANT_ROUTE
AGENT_ASSERTION_ROUTE = "/v1/nip-fi/agent-assertion"
AGENT_ASSERTION_PATH = ROUTE_PREFIX + AGENT_ASSERTION_ROUTE
AGENT_REVOKE_ROUTE = "/v1/nip-fi/agent-revoke"
