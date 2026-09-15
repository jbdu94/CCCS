#!/bin/bash
# Fully destroys the sandbox: container, network, volume, and logs.
# Nothing about your org's real pipeline is touched by this lab or by this script.
set -e
docker compose down -v --remove-orphans
rm -f logs/events.jsonl
echo "Sandbox destroyed. Target container, network, and logs removed."
