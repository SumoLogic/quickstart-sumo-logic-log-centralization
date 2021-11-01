#!/bin/sh

export AWS_REGION="ap-southeast-1"
export AWS_PROFILE="personal"
# App to test
export AppName=guardduty
export InstallType=all

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

# App Details - Collector Configuration
export CollectorName="AWS-anpn-Collector-${AppName}-${InstallType}"

# AWS Quick Start configuration
#export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketName="aws-quickstart"
export QSS3BucketRegion="us-east-1"

if [[ "${InstallType}" == "all" ]]
then
    export InstallGuardDutyApp="Yes"
    export InstallGlobalGuardDutyApp="Yes"
    export CreateHttpLogsSource="Yes"
elif [[ "${InstallType}" == "onlyguraddutyapp" ]]
then
    export InstallGuardDutyApp="Yes"
    export InstallGlobalGuardDutyApp="No"
    export CreateHttpLogsSource="No"
elif [[ "${InstallType}" == "onlyguraddutybenchmarkapp" ]]
then
    export InstallGuardDutyApp="No"
    export InstallGlobalGuardDutyApp="Yes"
    export CreateHttpLogsSource="No"
elif [[ "${InstallType}" == "onlysource" ]]
then
    export InstallGuardDutyApp="No"
    export InstallGlobalGuardDutyApp="No"
    export CreateHttpLogsSource="Yes"
else
    echo "No Choice"
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./guardduty.template.yaml --region ${AWS_REGION} \
--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
--parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
QSS3BucketName="${QSS3BucketName}" InstallGuardDutyApp="${InstallGuardDutyApp}" CollectorName="${CollectorName}" \
QSS3BucketRegion="${QSS3BucketRegion}" CreateHttpLogsSource="${CreateHttpLogsSource}" InstallGlobalGuardDutyApp="${InstallGlobalGuardDutyApp}"





