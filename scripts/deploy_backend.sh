#!/usr/bin/env bash
# Deploy the backend to Cloud Run with secrets in Secret Manager.
#
#   PROJECT_ID=my-project ./scripts/deploy_backend.sh
#   (optional) MG_VIRUSTOTAL_API_KEY=... MG_SAFE_BROWSING_API_KEY=... MG_PROTECTED_DOMAINS=acme.com
#
# Idempotent: re-running updates the service and adds new secret versions only when you
# pass new values. Secrets are never printed.
set -euo pipefail

PROJECT_ID=${PROJECT_ID:?set PROJECT_ID}
REGION=${REGION:-me-west1}          # Tel Aviv; any Cloud Run region works
SERVICE=${SERVICE:-mailguard}
SA_NAME=${SERVICE}-run
SA="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

gcloud config set project "$PROJECT_ID" >/dev/null
gcloud services enable run.googleapis.com secretmanager.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com >/dev/null

# Dedicated, minimal service account: it can read its own secrets and nothing else.
gcloud iam service-accounts describe "$SA" >/dev/null 2>&1 || \
  gcloud iam service-accounts create "$SA_NAME" --display-name "MailGuard Cloud Run"

put_secret() { # name value
  local name=$1 value=$2
  [ -z "$value" ] && return 0
  if gcloud secrets describe "$name" >/dev/null 2>&1; then
    printf '%s' "$value" | gcloud secrets versions add "$name" --data-file=- >/dev/null
  else
    printf '%s' "$value" | gcloud secrets create "$name" --data-file=- --replication-policy=automatic >/dev/null
  fi
  gcloud secrets add-iam-policy-binding "$name" --member "serviceAccount:$SA" \
    --role roles/secretmanager.secretAccessor >/dev/null
}

# Generate the shared HMAC secret on first deploy only.
if ! gcloud secrets describe mg-hmac-secret >/dev/null 2>&1; then
  put_secret mg-hmac-secret "${MG_HMAC_SECRET:-$(openssl rand -hex 32)}"
fi
put_secret mg-virustotal-key "${MG_VIRUSTOTAL_API_KEY:-}"
put_secret mg-safe-browsing-key "${MG_SAFE_BROWSING_API_KEY:-}"

SECRETS="MG_HMAC_SECRET=mg-hmac-secret:latest"
# Key rotation (see README): store the old key as mg-hmac-secret-previous, add a new version of
# mg-hmac-secret, redeploy, update the add-on, then delete the previous secret and redeploy.
gcloud secrets describe mg-hmac-secret-previous >/dev/null 2>&1 && SECRETS+=",MG_HMAC_SECRET_PREVIOUS=mg-hmac-secret-previous:latest"
gcloud secrets describe mg-virustotal-key >/dev/null 2>&1 && SECRETS+=",MG_VIRUSTOTAL_API_KEY=mg-virustotal-key:latest"
gcloud secrets describe mg-safe-browsing-key >/dev/null 2>&1 && SECRETS+=",MG_SAFE_BROWSING_API_KEY=mg-safe-browsing-key:latest"

# "^@^" switches gcloud's list delimiter so MG_PROTECTED_DOMAINS may contain commas.
# --allow-unauthenticated: Apps Script cannot attach a Cloud Run IAM token, so requests
# are authenticated at the application layer (HMAC). --max-instances 1 keeps the
# in-memory replay cache and rate limiter consistent (see README, "Trade-offs").
gcloud run deploy "$SERVICE" \
  --source "$ROOT/backend" \
  --region "$REGION" \
  --service-account "$SA" \
  --allow-unauthenticated \
  --set-secrets "$SECRETS" \
  --set-env-vars "^@^MG_ENV=prod@MG_PROTECTED_DOMAINS=${MG_PROTECTED_DOMAINS:-}" \
  --max-instances 1 --concurrency 20 --memory 512Mi --cpu 1 --timeout 30 \
  --ingress all

URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --format 'value(status.url)')
echo
echo "Backend deployed: $URL"
echo "Health check:     curl $URL/healthz"
echo
echo "Next, in the Apps Script project (Project Settings -> Script properties):"
echo "  BACKEND_URL = $URL"
echo "  HMAC_SECRET = (run: gcloud secrets versions access latest --secret mg-hmac-secret)"
echo "and add $URL/ to urlFetchWhitelist in addon/appsscript.json."
