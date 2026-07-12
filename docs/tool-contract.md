# Tool contract

The server registers 14 tools for local MCP transports. Remote Streamable HTTP
publishes the seven read-only tools marked `remote` below.

| Tool | Local | Remote | Behavior |
| --- | --- | --- | --- |
| `easypanel_capabilities` | yes | no | Sanitized compatibility profile |
| `easypanel_list_projects` | yes | yes | Allowlisted projects |
| `easypanel_list_services` | yes | yes | Sanitized service summaries |
| `easypanel_inspect_service` | yes | yes | Positive service projection |
| `easypanel_check_service_health` | yes | yes | Status/readiness projection |
| `easypanel_plan_service` | yes | no | Desired-state plan |
| `easypanel_apply_service` | yes | no | Apply one approved service plan |
| `easypanel_change_service_state` | yes | no | Plan/apply start, stop, restart |
| `easypanel_deploy_service` | yes | no | Plan/apply an App deployment |
| `easypanel_list_deployments` | yes | yes | Bounded deployment summaries |
| `easypanel_get_deployment_status` | yes | yes | Target-bound deployment status |
| `easypanel_get_sanitized_logs` | yes | yes | Fixed logs-disabled policy message |
| `easypanel_rotate_deploy_webhook` | yes | no | Approved rotation to a private sink |
| `easypanel_destroy_service` | yes | no | Plan/apply exact service destruction |

Remote HTTP does not expose a hidden route for the omitted tools. A rejected
remote call returns a fixed `REMOTE_TOOL_DENIED` response before it reaches the
SDK or the operator.

## Mutation lifecycle

Local mutation tools use a two-phase shape. Omitting `planHash` creates or reuses a
target-bound plan. Supplying the returned `planHash` attempts the operation after
policy, approval, precondition, and capability checks. The apply path verifies the
target-bound result before recording audit state.

Critical operations require separate `approval` and `confirmation` artifacts.
Artifacts are one-time, private files with a short expiration. A plan or approval
string copied from an MCP transcript is not authorization.

## Output rules

Tool output is a JSON text projection. It may contain project names, service names,
supported source metadata, bounded resources, status, and domains. It must not
contain environment values, passwords, tokens, raw upstream envelopes, runtime
logs, arbitrary URLs, or opaque upstream error bodies.
