#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=waf
export InstallType=sourcewithoutbucket

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoOrganizationId=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

# App Details - Collector Configuration
export CollectorName="AWS-Sourabh-Collector-${AppName}-${InstallType}"

export LogsS3BucketName="waf-${AppName}-${InstallType}"

export DeliveryStreamName="stream-${AppName}-${InstallType}"

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketRegion="us-east-1"

if [[ "${InstallType}" == "all" ]]
then
    export InstallApp="Yes"
    export CreateS3Bucket="Yes"
    export CreateS3Source="Yes"
    export CreateDeliveryStream="Yes"
elif [[ "${InstallType}" == "onlyapp" ]]
then
    export InstallApp="Yes"
    export CreateS3Bucket="No"
    export CreateS3Source="No"
    export CreateDeliveryStream="No"
elif [[ "${InstallType}" == "sourcewithoutbucket" ]]
then
    export InstallApp="Yes"
    export CreateS3Bucket="No"
    export CreateS3Source="Yes"
    export CreateDeliveryStream="Yes"
    export LogsS3BucketName="lambda-all-randmomstring"
else
    echo "No Choice"
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./waf.template.yaml --region ${AWS_REGION} \
--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
--parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
QSS3BucketName="${QSS3BucketName}" InstallApp="${InstallApp}" CollectorName="${CollectorName}" \
QSS3BucketRegion="${QSS3BucketRegion}" LogsS3BucketName="${LogsS3BucketName}" CreateS3Source="${CreateS3Source}" \
CreateS3Bucket="${CreateS3Bucket}" SumoOrganizationId="${SumoOrganizationId}" DeliveryStreamName="${DeliveryStreamName}" \
CreateDeliveryStream="${CreateDeliveryStream}"





