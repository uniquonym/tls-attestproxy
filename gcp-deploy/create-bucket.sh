#!/bin/bash

. .config

gcloud storage buckets create --project="$PROJECT" --location="$REGION" "gs://$ASSET_BUCKET"

gcloud storage buckets add-iam-policy-binding "gs://$ASSET_BUCKET" "--member=serviceAccount:service-$PROJECTNO@gcp-sa-vmmigration.iam.gserviceaccount.com" --role=roles/storage.objectViewer
