#!/bin/sh

export AWS_REGION="us-east-1"
export AWS_PROFILE="personal"
# App to test
export AppName=vpc
export InstallType=all

# Sumo Logic Access Configuration
export SumoAccessID=""
export SumoAccessKey=""
export SumoDeployment="us1"
export RemoveSumoResourcesOnDeleteStack=true

export CloudTrailSourceCategory="aws/cloud"
export VPCFlowLogsSourceCategory="aws/vpc"
export ElasticLoadBalancerSourceCategory="aws/elb"

# AWS Quick Start configuration
export QSS3BucketName="sumologiclambdahelper"
export QSS3BucketRegion="us-east-1"

# Stack Name
export stackName="${AppName}-${InstallType}"

aws cloudformation deploy --profile ${AWS_PROFILE} --template-file ./threatintel.template.yaml --region ${AWS_REGION} \
--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --stack-name ${stackName} \
--parameter-overrides SumoDeployment="${SumoDeployment}" SumoAccessID="${SumoAccessID}" SumoAccessKey="${SumoAccessKey}" \
RemoveSumoResourcesOnDeleteStack="${RemoveSumoResourcesOnDeleteStack}" \
QSS3BucketName="${QSS3BucketName}" QSS3BucketRegion="${QSS3BucketRegion}" CloudTrailSourceCategory="${CloudTrailSourceCategory}" \
VPCFlowLogsSourceCategory="${VPCFlowLogsSourceCategory}" ElasticLoadBalancerSourceCategory="${ElasticLoadBalancerSourceCategory}"s
