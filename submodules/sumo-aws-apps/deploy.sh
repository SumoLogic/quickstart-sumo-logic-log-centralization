#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=$1
export InstallType=$2

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoOrganizationId=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

# App Details - Collector Configuration
export CollectorName="AWS-Sourabh-Collector${AppName}-${InstallType}"

# App Details - Bucket Details
export BucketName="sourabh-bucket-quickstart-${InstallType}"

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper-${AWS_REGION}"

if [[ "${InstallType}" == "configall" ]]
then
    export InstallApp="Yes"
    export EnableConfig="Yes"
    export CreateSNSTopic="Yes"
    export CreateHttpLogsSource="Yes"
elif [[ "${InstallType}" == "confignos3" ]]
then
    export InstallApp="Yes"
    export EnableConfig="No"
    export CreateSNSTopic="Yes"
    export CreateHttpLogsSource="Yes"
elif [[ "${InstallType}" == "confignosns" ]]
then
    export InstallApp="Yes"
    export EnableConfig="No"
    export CreateSNSTopic="No"
    # Please put an existing topic name.
    export TopicName="SumoSNSTopic-config-configall"
    export CreateHttpLogsSource="Yes"
elif [[ "${InstallType}" == "configapponly" ]]
then
    export InstallApp="Yes"
    export EnableConfig="No"
    export CreateSNSTopic="No"
    export CreateHttpLogsSource="No"
else
    echo "No Valid Choice."
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./${AppName}/${AppName}.template.yaml --region ${AWS_REGION}\
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
    --parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
    SumoOrganizationId="${SumoOrganizationId}" RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
    QSS3BucketName="${QSS3BucketName}" InstallApp="${InstallApp}" CollectorName="${CollectorName}" BucketName="${BucketName}" \
    EnableConfig="${EnableConfig}" CreateSNSTopic="${CreateSNSTopic}" CreateHttpLogsSource="${CreateHttpLogsSource}" TopicName="${TopicName}"
 


