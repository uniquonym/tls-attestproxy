#!/bin/bash -e

if [[ ! -f .config ]]; then
    echo "Copy config.tmpl to .config and edit to your settings"
    exit 1
fi

. .config

echo Deleting image. Failing if this is first run is expected and is not a problem.

gcloud compute instances delete "$MAIN_INSTANCE_NAME" \
    --quiet \
    "--project=$PROJECT" \
    "--zone=$ZONE" || true

gcloud compute instances create "$MAIN_INSTANCE_NAME" \
    "--project=$PROJECT" \
    "--zone=$ZONE" \
    "--machine-type=$MAIN_INSTANCE_TYPE" \
    "--network-interface=network-tier=STANDARD,stack-type=IPV4_ONLY,subnet=$SUBNET" \
    --maintenance-policy=MIGRATE \
    --provisioning-model=STANDARD \
    "--service-account=$PROJECTNO-compute@developer.gserviceaccount.com" \
    "--scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/logging.write,https://www.googleapis.com/auth/monitoring.write,https://www.googleapis.com/auth/service.management.readonly,https://www.googleapis.com/auth/servicecontrol,https://www.googleapis.com/auth/trace.append" \
    "--create-disk=auto-delete=yes,boot=yes,device-name=$MAIN_INSTANCE_NAME,image=projects/$PROJECT/global/images/$IMAGE_NAME,mode=rw,size=10,type=pd-standard" \
    --shielded-secure-boot \
    --shielded-vtpm \
    --shielded-integrity-monitoring
