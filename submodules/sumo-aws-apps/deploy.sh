#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=$1
export InstallType=$2

# Sumo Logic Access Configuration
export SumoAccessID="suv1UhvjV0PgE0"
export SumoAccessKey="P0jqVLlNzWwYNAkXwF4SPWVlOMKnll8M9qlAcgrTuDiaqEBxvjyKamp4nzE8wM4L"
export SumoOrganizationId="0000000000285A74"
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
else
    echo "No Valid Choice."
fi

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./${AppName}/template.yaml --region ${AWS_REGION}\
    --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
    --parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
    SumoOrganizationId="${SumoOrganizationId}" RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
    QSS3BucketName="${QSS3BucketName}" InstallApp="${InstallApp}" CollectorName="${CollectorName}" BucketName="${BucketName}" \
    EnableConfig="${EnableConfig}" CreateSNSTopic="${CreateSNSTopic}" CreateHttpLogsSource="${CreateHttpLogsSource}"
 


