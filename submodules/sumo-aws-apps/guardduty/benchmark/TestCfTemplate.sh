#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=benchmark
export InstallType=all

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

# App Details - Collector Configuration
export CollectorName="AWS-Sourabh-Collector-${AppName}-${InstallType}"

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketRegion="us-east-1"

if [[ "${InstallType}" == "all" ]]
then
    export InstallApp="Yes"
    export CreateHttpLogsSource="Yes"
elif [[ "${InstallType}" == "onlyapp" ]]
then
    export InstallApp="Yes"
    export CreateHttpLogsSource="No"
elif [[ "${InstallType}" == "onlysource" ]]
then
    export InstallApp="No"
    export CreateHttpLogsSource="Yes"
else
    echo "No Choice"
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

if [[ "${AppName}" == "guardduty" ]]; then
    aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ././../guardduty.template.yaml --region ${AWS_REGION}\
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
    --parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
    RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
    QSS3BucketName="${QSS3BucketName}" InstallApp="${InstallApp}" CollectorName="${CollectorName}" \
    QSS3BucketRegion="${QSS3BucketRegion}" CreateHttpLogsSource="${CreateHttpLogsSource}"
elif [[ "${AppName}" == "benchmark" ]]; then
    aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./guarddutybenchmark.template.yaml --region ${AWS_REGION}\
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
    --parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
    RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
    QSS3BucketName="${QSS3BucketName}" InstallApp="${InstallApp}" CollectorName="${CollectorName}" \
    QSS3BucketRegion="${QSS3BucketRegion}" CreateHttpLogsSource="${CreateHttpLogsSource}"
fi





