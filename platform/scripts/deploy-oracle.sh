#!/usr/bin/env bash
# Deploys the committed HEAD of platform/ to the Oracle VM (ruyalab-apps) that serves ruyashield.ruyalab.com.
#
#   platform/scripts/deploy-oracle.sh            # deploy HEAD
#   DEPLOY_HOST=ubuntu@1.2.3.4 SSH_KEY=~/.ssh/key platform/scripts/deploy-oracle.sh
#
# Server layout (set up once, by hand):
#   /srv/ruyashield/app          live build (WorkingDirectory of ruyashield-web and ruyashield-worker)
#   /srv/ruyashield/app.prev     the previous build, kept for rollback
#   /srv/ruyashield/backups      pg_dump before every migration (last 10 kept)
#   /etc/ruyashield/env          production settings (root:ruya 640), loaded by systemd
#
# Steps: upload a git archive -> npm ci + next build in a staging dir (live site keeps serving) -> back up the
# database -> run migrations -> swap staging in and restart both services -> health check, and put the
# previous build back if the check fails. Migrations are additive; a rollback does not undo them.
set -euo pipefail

HOST="${DEPLOY_HOST:-ubuntu@137.23.55.106}"
KEY="${SSH_KEY:-$HOME/.ssh/ruyaflow_oracle}"
ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
SHA="$(git -C "$ROOT" rev-parse --short HEAD)"

if [ -n "$(git -C "$ROOT" status --porcelain -- platform)" ]; then
  echo "platform/ has uncommitted changes; commit first so the deployed build matches a commit." >&2
  exit 1
fi

ssh_() { ssh -i "$KEY" -o BatchMode=yes -o ConnectTimeout=15 "$HOST" "$@"; }

echo "==> Uploading $SHA"
git -C "$ROOT" archive --format=tar.gz HEAD:platform | ssh_ "cat > /tmp/ruyashield-$SHA.tar.gz"

ssh_ "sudo SHA=$SHA bash -s" <<'REMOTE'
set -euo pipefail
BASE=/srv/ruyashield
STAGE=$BASE/app.next
# Runs a command as the ruya service user with the production environment loaded.
as_ruya() { (set -a; . /etc/ruyashield/env; set +a; cd "$STAGE_OR_APP" && setpriv --reuid=ruya --regid=ruya --init-groups -- "$@"); }

echo "==> Building $SHA in $STAGE"
rm -rf "$STAGE" && install -d -o ruya -g ruya "$STAGE"
tar -xzf "/tmp/ruyashield-$SHA.tar.gz" -C "$STAGE" && rm -f "/tmp/ruyashield-$SHA.tar.gz"
echo "$SHA" > "$STAGE/REVISION"
chown -R ruya:ruya "$STAGE"
STAGE_OR_APP=$STAGE
# NODE_ENV=production (from the env file) would skip devDependencies, which the build and the worker (tsx) need.
as_ruya env HOME=$BASE npm ci --include=dev --no-audit --no-fund --loglevel=error
as_ruya env HOME=$BASE NEXT_TELEMETRY_DISABLED=1 node node_modules/next/dist/bin/next build > "$STAGE/build.log" 2>&1 \
  || { tail -40 "$STAGE/build.log"; echo "Build failed; the live site was not touched." >&2; exit 1; }

echo "==> Backing up the database"
install -d -o ruya -g ruya -m 750 $BASE/backups
DUMP=$BASE/backups/ruyashield-$(date -u +%Y%m%dT%H%M%SZ)-before-$SHA.dump
(set -a; . /etc/ruyashield/env; set +a; pg_dump -Fc -f "$DUMP" "$DATABASE_OWNER_URL")
chown ruya:ruya "$DUMP"
ls -1t $BASE/backups/*.dump | tail -n +11 | xargs -r rm -f
echo "    $DUMP ($(du -h "$DUMP" | cut -f1))"

echo "==> Migrating"
as_ruya node node_modules/tsx/dist/cli.mjs scripts/migrate.mts

echo "==> Switching to $SHA"
systemctl stop ruyashield-worker ruyashield-web
rm -rf $BASE/app.prev
mv $BASE/app $BASE/app.prev
mv "$STAGE" $BASE/app
systemctl start ruyashield-web ruyashield-worker

ok=""
for _ in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:3200/ || true)
  if [ "$code" = 200 ] && systemctl is-active -q ruyashield-worker; then ok=1; break; fi
  sleep 2
done
if [ -z "$ok" ]; then
  echo "Health check failed; restoring the previous build." >&2
  journalctl -u ruyashield-web -u ruyashield-worker -n 30 --no-pager >&2 || true
  systemctl stop ruyashield-worker ruyashield-web
  mv $BASE/app "$BASE/app.failed-$SHA" && mv $BASE/app.prev $BASE/app
  systemctl start ruyashield-web ruyashield-worker
  exit 1
fi
echo "==> Live: $SHA"
REMOTE
