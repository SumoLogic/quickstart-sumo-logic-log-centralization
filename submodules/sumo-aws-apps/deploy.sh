#!/bin/sh

echo -e 'Welcome to SumoLogic Amazon Apps'
read -p 'Enter the S3 bucket name to upload the SAM applications: '  sam_s3_bucket
echo 'Enter the Sumlogic access details'
read -p 'SumoDeployment (us2/us1): ' sumo_deployment
read -p 'SumoAccessID:' sumo_access_id
read -p 'SumoAccessKey: ' sumo_access_key
echo 'Please enter the app number to install(1/2....):'
echo '1. Amazon GuardDuty Benchmark'
echo '2. Amazon GuardDuty'
echo '3. Amazon S3 Audit'
echo '4. AWS WAF'
echo '5. AWS Config'
echo '6. AWS CloudTrail'
echo '7. Amazon VPC Flow Logs'
echo '8. CIS AWS Foundations Benchmark'
echo '9. PCI Compliance for Amazon VPC Flow Logs'
echo '10. PCI Compliance for AWS Cloud Trail App'
echo '11. Security Hub'

guard_duty_benchmark()
{
  	cd sumologic-app-utils 
	rm -r .aws-sam
	sam build -t sumo_app_utils.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/guardduty/benchmark
	rm -r .aws-sam
	sam build -t template.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategoryName: ' SourceCategoryName
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack
	stack_name=sumologic-guardduty-benchmark-$(date "+%Y-%m-%d-%H-%M-%S")
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategoryName=$SourceCategoryName \
	SourceName=$SourceName \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack 
	
	
}
guard_duty()
{
  	cd sumologic-app-utils 
	rm -r .aws-sam
	sam build -t sumo_app_utils.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/guardduty
	rm -r .aws-sam
	sam build -t template.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategoryName: ' SourceCategoryName
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack
	stack_name=sumologic-guardduty-$(date "+%Y-%m-%d-%H-%M-%S")
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategoryName=$SourceCategoryName \
	SourceName=$SourceName \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \
	
}

vpc_flow_logs()
{
  	cd sumologic-app-utils 
	rm -r .aws-sam
	sam build -t sumo_app_utils.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/vpc-flow-logs
	rm -r .aws-sam
	sam build -t template.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategoryName: ' SourceCategoryName
	read -p 'PathExpression: ' PathExpression
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	read -p 'LogsTargetS3BucketName: ' LogsTargetS3BucketName
	read -p 'CreateTargetS3Bucket (yes/no): ': CreateTargetS3Bucket
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack
	read -p 'Amazon VPC Flow Logs App SourceCategoryName: ' VPCFlowLogAppSourceCategoryName
	
	stack_name=sumologic-vpc-flow-logs-$(date "+%Y-%m-%d-%H-%M-%S")
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategoryName=$SourceCategoryName \
	ExternalID=$ExternalID \
	PathExpression=$PathExpression \
	LogsTargetS3BucketName=$LogsTargetS3BucketName \
	CreateTargetS3Bucket=$CreateTargetS3Bucket \
	VPCFlowLogAppSourceCategoryName=$VPCFlowLogAppSourceCategoryName \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \
	
}
s3_audit()
{
  	cd sumologic-app-utils 
	rm -r .aws-sam
	sam build -t sumo_app_utils.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/s3-audit
	rm -r .aws-sam
	sam build -t template.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategoryName: ' SourceCategoryName
	read -p 'PathExpression: ' PathExpression
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	read -p 'AccessLogsTargetS3BucketName: ':  AccessLogsTargetS3BucketName
	read -p 'CreateTargetS3Bucket (yes/no): ': CreateTargetS3Bucket
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack
	
	stack_name=sumologic-s3-audit-$(date "+%Y-%m-%d-%H-%M-%S")
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategoryName=$SourceCategoryName \
	ExternalID=$ExternalID \
	PathExpression=$PathExpression \
	AccessLogsTargetS3BucketName=$AccessLogsTargetS3BucketName \
	CreateTargetS3Bucket=$CreateTargetS3Bucket \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \
	
}
waf()
{
  	cd sumologic-app-utils 
	rm -r .aws-sam
	sam build -t sumo_app_utils.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/WAF
	rm -r .aws-sam
	sam build -t template.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	echo '\n-----SumoLogic configuration------\n'
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategoryName: ' SourceCategoryName
	read -p 'PathExpression: ' PathExpression
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	echo '\n-----Amazon KinesisFirehose DeliveryStream Configuration------\n'
	read -p 'DeliveryStreamName: ' DeliveryStreamName
	read -p 'KinesisDestinationS3BucketName: ' KinesisDestinationS3BucketName
	read -p 'CreateKinesisDestinationS3Bucket (yes/no) : ' CreateKinesisDestinationS3Bucket
	
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack
	
	stack_name=sumologic-waf-$(date "+%Y-%m-%d-%H-%M-%S")
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategoryName=$SourceCategoryName \
	ExternalID=$ExternalID \
	PathExpression=$PathExpression \
	DeliveryStreamName=$DeliveryStreamName \
	KinesisDestinationS3BucketName=$KinesisDestinationS3BucketName \
	CreateKinesisDestinationS3Bucket=$CreateKinesisDestinationS3Bucket \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \
	
}
config()
{
	cd sumologic-app-utils 
	rm -r .aws-sam
	sam build -t sumo_app_utils.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/config
	rm -r .aws-sam
	sam build -t template.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	echo '\n-----SumoLogic configuration------\n'
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategoryName: ' SourceCategoryName
	read -p 'PathExpression: ' PathExpression
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	read -p 'AccessLogsTargetS3BucketName: ':  AccessLogsTargetS3BucketName
	read -p 'CreateTargetS3Bucket (yes/no): ': CreateTargetS3Bucket
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack

	stack_name=sumologic-config-stack-$(date "+%Y-%m-%d-%H-%M-%S")
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategoryName=$SourceCategoryName \
	ExternalID=$ExternalID \
	PathExpression=$PathExpression \
	ConfigTargetS3BucketName=$AccessLogsTargetS3BucketName \
	CreateTargetS3Bucket=$CreateTargetS3Bucket \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \

}
cloudtrail()
{
	cd sumologic-app-utils 
	rm -r .aws-sam
	sam build -t sumo_app_utils.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/cloudtrail
	rm -r .aws-sam
	sam build -t template.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	echo '\n-----SumoLogic configuration------\n'
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategoryName: ' SourceCategoryName
	read -p 'PathExpression: ' PathExpression
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	read -p 'AccessLogsTargetS3BucketName: ':  AccessLogsTargetS3BucketName
	read -p 'CreateTargetS3Bucket (yes/no): ': CreateTargetS3Bucket
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack

	stack_name=sumologic-cloudtrail-stack-$(date "+%Y-%m-%d-%H-%M-%S")
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategoryName=$SourceCategoryName \
	ExternalID=$ExternalID \
	PathExpression=$PathExpression \
	CloudTrailTargetS3BucketName=$AccessLogsTargetS3BucketName \
	CreateTargetS3Bucket=$CreateTargetS3Bucket \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \

}
cis_foundations()
{
	cd sumologic-app-utils 
	rm -r .aws-sam
	sam build -t sumo_app_utils.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/CIS-Foundations
	rm -r .aws-sam
	sam build -t template.yaml
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	echo '\n-----SumoLogic configuration------\n'
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategoryName: ' SourceCategoryName
	read -p 'PathExpression: ' PathExpression
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	read -p 'AccessLogsTargetS3BucketName: ': AccessLogsTargetS3BucketName
	read -p 'CreateTargetS3Bucket (yes/no): ': CreateTargetS3Bucket
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack

	stack_name=sumologic-cis-foundations-stack-$(date "+%Y-%m-%d-%H-%M-%S")
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategoryName=$SourceCategoryName \
	ExternalID=$ExternalID \
	PathExpression=$PathExpression \
	CISTargetS3BucketName=$AccessLogsTargetS3BucketName \
	CreateTargetS3Bucket=$CreateTargetS3Bucket \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \

}
pci_compliance_vpc_flow()
{
  	cd sumo-s3-source-utils 
	rm -r .aws-sam
	sam build -t template.yaml
	file_name=sumo-s3-source-utils-$(date "+%Y-%m-%d-%H-%M-%S").yaml
	region=$(aws configure get region)
	template_url=https://s3.$region.amazonaws.com/$sam_s3_bucket/$file_name
	
	echo $file_name
	echo $template_url
	sam package --output-template $file_name --s3-bucket $sam_s3_bucket
	echo uploading the s3 source utils to s3...
	aws s3 cp $file_name s3://$sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/pci-compliance-vpc-flow
	rm -r .aws-sam
	sam build -t template.yaml --parameter-overrides 'ParameterKey=S3SourceUtilTempalteS3Url,ParameterValue=$template_url'
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	echo '\n-----SumoLogic configuration------\n'
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategory: ' SourceCategory
	read -p 'PathExpression: ' PathExpression
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	read -p 'PCIVpcFlowAppSourceCategory': PCIVpcFlowAppSourceCategory
	echo '\n-----Amazon Configuration------\n'
	read -p 'LogsTargetS3BucketName: ':  LogsTargetS3BucketName
	read -p 'CreateTargetS3Bucket (yes/no): ': CreateTargetS3Bucket
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack
	
	
	stack_name=sumo-pci-compliance-for-vpc-flow-$(date "+%Y-%m-%d-%H-%M-%S")
	
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategory=$SourceCategory \
	ExternalID=$ExternalID \
	PathExpression=$PathExpression \
	LogsTargetS3BucketName=$LogsTargetS3BucketName \
	CreateTargetS3Bucket=$CreateTargetS3Bucket \
	VPCFlowLogAppSourceCategoryName=$VPCFlowLogAppSourceCategoryName \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \
	PCIVpcFlowAppSourceCategory=$PCIVpcFlowAppSourceCategory \
	S3SourceUtilTempalteS3Url=$template_url \
	

	cd ..
	
}

pci_compliance_cloudtrail()
{
  	cd sumo-s3-source-utils 
	rm -r .aws-sam
	sam build -t template.yaml
	file_name=sumo-s3-source-utils-$(date "+%Y-%m-%d-%H-%M-%S").yaml
	region=$(aws configure get region)
	template_url=https://s3.$region.amazonaws.com/$sam_s3_bucket/$file_name
	
	echo $file_name
	echo $template_url
	sam package --output-template $file_name --s3-bucket $sam_s3_bucket
	echo uploading the s3 source utils to s3...
	aws s3 cp $file_name s3://$sam_s3_bucket
	#sam deploy --template-file packaged.yaml --stack-name  sumologic-app-utils --capabilities CAPABILITY_IAM
	echo Installing..........
	cd ..\/pci-compliance-cloudttrial-app
	rm -r .aws-sam
	sam build -t template.yaml --parameter-overrides 'ParameterKey=S3SourceUtilTempalteS3Url,ParameterValue=$template_url'
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	echo '\n-----SumoLogic configuration------\n'
	read -p 'CollectorName: ' collector_name
	read -p 'SourceName; ' SourceName
	read -p 'SourceCategory: ' SourceCategory
	read -p 'PathExpression: ' PathExpression
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	read -p 'PCICloudTrailAppSourceCategory': PCICloudTrailAppSourceCategory
	echo '\n-----Amazon Configuration------\n'
	read -p 'LogsTargetS3BucketName: ':  LogsTargetS3BucketName
	read -p 'CreateTargetS3Bucket (yes/no): ': CreateTargetS3Bucket
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack
	
	
	stack_name=sumo-pci-compliance-for-cloudtrail-app-$(date "+%Y-%m-%d-%H-%M-%S")
	
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	SourceCategory=$SourceCategory \
	ExternalID=$ExternalID \
	PathExpression=$PathExpression \
	LogsTargetS3BucketName=$LogsTargetS3BucketName \
	CreateTargetS3Bucket=$CreateTargetS3Bucket \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \
	PCICloudTrailAppSourceCategory=$PCICloudTrailAppSourceCategory \
	S3SourceUtilTempalteS3Url=$template_url \
	

	cd ..
	
}
security_hub()
{
  	cd security-hub
	rm -r .aws-sam
	sam build -t template.yaml
	
	sam package --output-template packaged.yaml --s3-bucket $sam_s3_bucket
	
	echo '\n-----SumoLogic configuration------\n'
	read -p 'EnableSecurityHub ("yes"/"no"): ' EnableSecurityHub
	read -p 'CollectorName: ' collector_name
	read -p 'ConnectionName; ' ConnectionName
	read -p 'SourceName: ' SourceName
	read -p 'PathExpression: ' PathExpression
	read -p 'SourceCategory: ' SourceCategory
	read -p 'ExternalID (deployment:accountId. Eg. us1:0000000000000131)': ExternalID
	
	echo '\n-----Amazon Configuration------\n'
	read -p 'LogsTargetS3BucketName: ':  LogsTargetS3BucketName
	read -p 'CreateTargetS3Bucket (yes/no): ': CreateTargetS3Bucket
	read -p 'RemoveSumoResourcesOnDeleteStack(true/false): ' RemoveSumoResourcesOnDeleteStack
	
	
	stack_name=sumo-security-hub-$(date "+%Y-%m-%d-%H-%M-%S")
	
	sam deploy --template-file packaged.yaml --stack-name  $stack_name \
	--capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM CAPABILITY_AUTO_EXPAND \
	--parameter-overrides SumoDeployment=$sumo_deployment \
	SumoAccessID=$sumo_access_id SumoAccessKey=$sumo_access_key \
	CollectorName=$collector_name \
	SourceName=$SourceName \
	ConnectionName=$ConnectionName \
	SourceCategoryName=$SourceCategory \
	PathExpression=$PathExpression \
	EnableSecurityHub=$EnableSecurityHub \
	S3BucketName=$LogsTargetS3BucketName \
	CreateTargetS3Bucket=$CreateTargetS3Bucket \
	ExternalID=$ExternalID \
	RemoveSumoResourcesOnDeleteStack=$RemoveSumoResourcesOnDeleteStack \

	cd ..
	
}
while :
do
  read INPUT_STRING
  case $INPUT_STRING in
	1)
		guard_duty_benchmark
		;;
	2)
		guard_duty
		;;
	3)
		s3_audit
		;;
	4)
		waf
		;;
	5)
		config 
		;;
	6)
		cloudtrail 
		;;
	7)
		vpc_flow_logs 
		;;
	8) 
		cis_foundations
		;;
	9) 
		pci_compliance_vpc_flow
		;;
	10) 
		pci_compliance_cloudtrail
		;;
	11) 
		security_hub
		;;
	bye)
		echo "See you again!"
		break
		;;
	*)
		echo "Sorry, I don't understand"
		;;
  esac
done





 


