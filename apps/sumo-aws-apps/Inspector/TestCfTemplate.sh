#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=Inspector
export InstallType=onlyinspectorapp

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoOrganizationId=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

# App Details - Collector Configuration
export CollectorName="AWS-Lang-Collector-${AppName}-${InstallType}"

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketRegion=${AWS_REGION}

if [[ "${InstallType}" == "all" ]]
then
    export InstallAmazonInspectorApp="Yes"
    export CreateHttpLogsSource="Yes"
elif [[ "${InstallType}" == "onlyinspectorapp" ]]
then
	export InstallAmazonInspectorApp="Yes"
    export CreateHttpLogsSource="No"
elif [[ "${InstallType}" == "onlysource" ]]
then
	export InstallAmazonInspectorApp="No"
    export CreateHttpLogsSource="Yes"
elif [[ "${InstallType}" == "enablelogging" ]]
else
    echo "No Choice"
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./inspector.template.yaml --region ${AWS_REGION} \
--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
--parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
QSS3BucketName="${QSS3BucketName}" InstallAmazonInspectorApp="${InstallGuardDutyApp}" CollectorName="${CollectorName}" \
QSS3BucketRegion="${QSS3BucketRegion}" CreateHttpLogsSource="${CreateHttpLogsSource}"





