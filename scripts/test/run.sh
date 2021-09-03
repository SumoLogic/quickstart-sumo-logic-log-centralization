#!/bin/sh

# Dependencies Installation
    # install cfn-nag https://github.com/stelligent/cfn_nag#installation
        # For mac below commands
            # brew install ruby brew-gem
            # brew gem install cfn-nag
    # pip install sumologic-cfn-tester

# sh uploadToS3.sh and provide the bucket details below
bucket_name="sumologiclambdahelper-2-ap-south-1"
region="ap-south-1"
repo_dir_path="/Users/hpal/git/quickstart-sumo-logic-log-centralization/"

aws s3 cp "$repo_dir_path" s3://$bucket_name/quickstart-sumo-logic-log-centralization/ --recursive --exclude '.git/*' --exclude '.idea/*' --acl public-read
export AWS_PROFILE="personal"
export ENTERPRISE_ACCESS_ID=""
export ENTERPRISE_ACCESS_KEY=""
export ENTERPRISE_DEPLOYMENT="us1"
export US1_ENTERPRISE_ORG_ID=""
export EXISTING_VPC_ID="vpc-928c6bfa"
export EXISTING_SUBNET_ID="subnet-9d9d6fe6"
export QSS3BucketName="$bucket_name"
export QSS3BucketRegion="$region"
sumocfntester -f test.yaml -d true
