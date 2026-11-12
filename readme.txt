AgentGate compiles a local preinstalled-agent network submission into a return list, review package, remediation plan, and optional SQLite review history.

Run acceptance:
python3 -m agentgate compile fixtures/compliant --output /tmp/agentgate-output --store /tmp/agentgate-review.sqlite3 --summary

Run tests:
python3 -m unittest discover -s tests -v

Run build check:
python3 -m compileall -q agentgate tests

Inspect persisted remediation plan:
python3 -m agentgate artifact --store /tmp/agentgate-review.sqlite3 --bundle-id AGB-NORTHWIND-202611 --revision r1 --name remediation-plan
