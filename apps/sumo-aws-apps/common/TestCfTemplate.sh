#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=common
export InstallType=all

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoOrganizationId=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

# App Details - Collector Configuration
export CollectorName="AWS-Sourabh-Collector-${AppName}-${InstallType}"

export BucketName="common-${AppName}-${InstallType}"

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketRegion=${AWS_REGION}

if [[ "${InstallType}" == "all" ]]
then
    export CreateCollector="Yes"
    export CreateBucket="Yes"
    export CreateTrail="Yes"
elif [[ "${InstallType}" == "onlycollector" ]]
then
    export CreateCollector="Yes"
    export CreateBucket="No"
    export CreateTrail="No"
elif [[ "${InstallType}" == "onlybucket" ]]
then
    export CreateCollector="No"
    export CreateBucket="Yes"
    export CreateTrail="No"
elif [[ "${InstallType}" == "onlytrail" ]]
then
    export CreateCollector="No"
    export CreateBucket="Yes"
    export CreateTrail="Yes"
else
    echo "No Choice"
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./resources.template.yaml --region ${AWS_REGION} \
--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
--parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
QSS3BucketName="${QSS3BucketName}" CreateCollector="${CreateCollector}" CollectorName="${CollectorName}" \
QSS3BucketRegion="${QSS3BucketRegion}" BucketName="${BucketName}" CreateBucket="${CreateBucket}" \
CreateTrail="${CreateTrail}" SumoOrganizationId="${SumoOrganizationId}"





