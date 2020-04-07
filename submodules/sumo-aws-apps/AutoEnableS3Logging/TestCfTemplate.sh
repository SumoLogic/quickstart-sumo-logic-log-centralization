#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=autoenable
export InstallType=S3

# App Details - Collector Configuration
export BucketName="lambda-all-randmomstring"

export BucketPrefix=${InstallType}"-LOGS"

export FilterExpression=""

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketRegion=${AWS_REGION}

if [[ "${InstallType}" == "VPC" ]]
then
    export EnableLogging="VPC"
elif [[ "${InstallType}" == "S3" ]]
then
    export EnableLogging="S3"
else
    echo "No Choice"
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./auto_enable_s3_logging.template.yaml --region ${AWS_REGION} \
--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
--parameter-overrides QSS3BucketName="${QSS3BucketName}" BucketName="${BucketName}" \
QSS3BucketRegion="${QSS3BucketRegion}" BucketPrefix="${BucketPrefix}" FilterExpression="${FilterExpression}" \
EnableLogging="${EnableLogging}"