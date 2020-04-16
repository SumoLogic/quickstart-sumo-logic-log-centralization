#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=vpc
export InstallType=enablevpcasdas

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoOrganizationId=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

# App Details - Collector Configuration
export CollectorName="AWS-Sourabh-Collector-${AppName}-${InstallType}"

export LogsS3BucketName="vpc-flow-logs-${AppName}-${InstallType}"

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketRegion=${AWS_REGION}

if [[ "${InstallType}" == "all" ]]
then
    export InstallVpcApp="Yes"
    export InstallPCIVpcApp="Yes"
    export CreateS3Bucket="Yes"
    export CreateS3Source="Yes"
elif [[ "${InstallType}" == "onlyvpcapp" ]]
then
    export InstallVpcApp="Yes"
    export InstallPCIVpcApp="No"
    export CreateS3Bucket="No"
    export CreateS3Source="No"
elif [[ "${InstallType}" == "onlypcivpcapp" ]]
then
    export InstallVpcApp="No"
    export InstallPCIVpcApp="Yes"
    export CreateS3Bucket="No"
    export CreateS3Source="No"
elif [[ "${InstallType}" == "sourcewithoutbucket" ]]
then
    export InstallVpcApp="Yes"
    export InstallPCIVpcApp="Yes"
    export CreateS3Bucket="No"
    export CreateS3Source="Yes"
    export LogsS3BucketName="sumologiclambdahelper-us-east-1"
elif [[ "${InstallType}" == "enablevpcasdas" ]]
then
    export InstallVpcApp="No"
    export InstallPCIVpcApp="No"
    export CreateS3Bucket="No"
    export CreateS3Source="No"
    export LogsS3BucketName="sumologiclambdahelper-us-east-1"
else
    echo "No Choice"
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./vpcflowlogs.template.yaml --region ${AWS_REGION} \
--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
--parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
QSS3BucketName="${QSS3BucketName}" InstallVpcApp="${InstallVpcApp}" CollectorName="${CollectorName}" \
QSS3BucketRegion="${QSS3BucketRegion}" LogsS3BucketName="${LogsS3BucketName}" CreateS3Source="${CreateS3Source}" \
CreateS3Bucket="${CreateS3Bucket}" InstallPCIVpcApp="${InstallPCIVpcApp}" SumoOrganizationId="${SumoOrganizationId}"