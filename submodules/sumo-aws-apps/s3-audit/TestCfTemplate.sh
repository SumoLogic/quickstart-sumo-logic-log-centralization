#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=s3audit
export InstallType=enablelogging

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoOrganizationId=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

# App Details - Collector Configuration
export CollectorName="AWS-Sourabh-Collector-${AppName}-${InstallType}"

export LogsS3BucketName="s3-audit-${AppName}-${InstallType}"

export FilterExpression="sumologiclambdahelper"

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketRegion=${AWS_REGION}

if [[ "${InstallType}" == "all" ]]
then
    export InstallApp="Yes"
    export CreateS3Bucket="Yes"
    export CreateS3AuditSource="Yes"
    export AutoEnableS3Logging="Yes"
elif [[ "${InstallType}" == "onlyapp" ]]
then
    export InstallApp="Yes"
    export CreateS3Bucket="No"
    export CreateS3AuditSource="No"
    export AutoEnableS3Logging="No"
elif [[ "${InstallType}" == "sourcewithoutbucket" ]]
then
    export InstallApp="No"
    export CreateS3Bucket="No"
    export CreateS3AuditSource="Yes"
    export AutoEnableS3Logging="No"
    export LogsS3BucketName="lambda-all-randmomstring"
elif [[ "${InstallType}" == "enablelogging" ]]
then
    export InstallApp="No"
    export CreateS3Bucket="No"
    export CreateS3AuditSource="No"
    export AutoEnableS3Logging="Yes"
    export LogsS3BucketName="lambda-all-randmomstring"
else
    echo "No Choice"
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./s3audit.template.yaml --region ${AWS_REGION} \
--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
--parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
QSS3BucketName="${QSS3BucketName}" InstallApp="${InstallApp}" CollectorName="${CollectorName}" \
QSS3BucketRegion="${QSS3BucketRegion}" LogsS3BucketName="${LogsS3BucketName}" CreateS3AuditSource="${CreateS3AuditSource}" \
CreateS3Bucket="${CreateS3Bucket}" SumoOrganizationId="${SumoOrganizationId}"





