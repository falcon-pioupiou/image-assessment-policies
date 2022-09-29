#!/bin/bash

# get API token
FALCON_API_BEARER_TOKEN=$(curl \
--silent \
--header "Content-Type: application/x-www-form-urlencoded" \
--data "client_id=${FALCON_CLIENT_ID}&client_secret=${FALCON_CLIENT_SECRET}" \
--request POST \
--url "https://api.crowdstrike.com/oauth2/token" | \
python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

RESPONSE=$(curl -s -X GET -H "Authorization: Bearer ${FALCON_API_BEARER_TOKEN}" \
            "https://container-upload.$FALCON_CLOUD_REGION.crowdstrike.com/policy-checks?policy_type=image-prevention-policy&repository=$IMAGE_REPO&tag=$IMAGE_TAG" |\
            jq -r '.resources[0]' )

DENY=$(echo $RESPONSE | jq -r '.deny')
ACTION=$(echo $RESPONSE | jq -r '.action')
POLICY_NAME=$(echo $RESPONSE | jq -r '.policy.name')
POLICY_DESCRIPTION=$(echo $RESPONSE | jq -r '.policy.description')
if [[ "$DENY" == "true" && "$ACTION" == "block" ]]; then
    echo "============================================================"
    echo "IMAGE BLOCKED DUE TO SECURITY POLICY"
    echo "${POLICY_NAME} - ${POLICY_DESCRIPTION}"
    echo "============================================================"
    echo " "
    echo "Malware :"
    curl -s -X GET -H "Authorization: Bearer ${FALCON_API_BEARER_TOKEN}" \
                    "https://container-upload.${FALCON_CLOUD_REGION}.crowdstrike.com/reports?repository=$IMAGE_REPO&tag=$IMAGE_TAG" |\
                    jq -r '.ELFBinaries[] | select(.Malicious == true) | "\(.Malicious) - \(.Permissions) : \(.Path)"'
    
    echo " "
    echo "Detections :"
    curl -s -X GET -H "Authorization: Bearer ${FALCON_API_BEARER_TOKEN}" \
                    "https://container-upload.${FALCON_CLOUD_REGION}.crowdstrike.com/reports?repository=$IMAGE_REPO&tag=$IMAGE_TAG" |\
                    jq -r '.Detections[].Detection | "\(.Severity) - \(.Type) - \(.Name) - \(.Title) - \(.Details.Match)"'
    
    echo " "
    echo "Vulnerabilities :"
    curl -s -X GET -H "Authorization: Bearer ${FALCON_API_BEARER_TOKEN}" \
                    "https://container-upload.${FALCON_CLOUD_REGION}.crowdstrike.com/reports?repository=$IMAGE_REPO&tag=$IMAGE_TAG" |\
                    jq -r '.Vulnerabilities[].Vulnerability | "\(.CVEID)\t\(.Product.PackageSource)\t\(.Details.exploited.status)\t\(.Details.severity)\t\(.Details.exploitability_score)"'
    
    sleep 1
    exit 1
else
    echo "IMAGE OK TO BE DEPLOYED ACCORDING TO IMAGE ASSESSMENT POLICY"
    exit 0
fi