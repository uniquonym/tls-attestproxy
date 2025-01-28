#!/bin/bash -e

if [[ ! -f .config ]]; then
    echo "Copy config.tmpl to .config and edit to your settings"
    exit 1
fi

. .config

if [[ ! -f ../result/tlsattest-x86_64.rawdisk ]]; then
    echo "Run buildimg.sh in level above first"
    exit 1
fi

mkdir -p output/image
cp ../result/tlsattest-x86_64.rawdisk output/image/disk.raw
# This makes subsequent runs succeed.
chmod u+w output/image/disk.raw

tar -C output/image -czf output/image.tar.gz disk.raw

gcloud storage cp "--project=$PROJECT" output/image.tar.gz "gs://$ASSET_BUCKET/image.tar.gz"

echo Cleaning up old images. Will fail if this is the first time - you can ignore this.
#gcloud migration vms image-imports delete "$IMAGE_NAME" \
#  "--project=$PROJECT" \
#  "--location=$REGION" || true
gcloud compute images delete "$IMAGE_NAME" \
  "--project=$PROJECT" || true       

echo Starting image creation...
gcloud compute images create "$IMAGE_NAME" \
    "--project=$PROJECT" \
    "--source-uri=gs://$ASSET_BUCKET/image.tar.gz" \
    "--storage-location=$REGION" \
    "--architecture=X86_64" \
    "--signature-database-file=../snakeoil-pesign/snakeoil.crt" \
    "--guest-os-features=UEFI_COMPATIBLE,SEV_CAPABLE,TDX_CAPABLE"

gcloud storage rm "--project=$PROJECT" "gs://$ASSET_BUCKET/image.tar.gz"
