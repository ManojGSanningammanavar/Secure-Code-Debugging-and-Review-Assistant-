#!/usr/bin/env bash
# Wipe the database and index (keeps trained models) so the demo starts fresh.
cd "$(dirname "$0")/.."
rm -f var/sentinel.db var/sentinel.db-wal var/sentinel.db-shm
rm -rf var/index var/workflow_outbox
echo "Demo data reset. Start the server again to re-seed."
