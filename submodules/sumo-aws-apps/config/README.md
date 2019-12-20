# sumologic-amazon-config
This solution installs the Config App, creates collectors/sources in Sumo Logic platform and deploys the resources in your AWS account using configuration provided at the time of SAM application deployment.


![SumoLogic Config App](https://user-images.githubusercontent.com/6774570/67530286-7d937b00-f673-11e9-8b91-f0331992821d.jpg)

### Resources in template.yaml
1.	List of Parameters user needs to input
2.	IAM role that assumes role from sumologic account and provides access to the S3 bucket
3.	Serverless lambda function to create collector, source, install app on sumologic console. This will output S3/Http source endpoint URL which is used in SNS subscription below
4.	S3 bucket with the name user provided as parameter. This bucket will capture logs from Config. 
5.	S3 bucket policy that allows read-write access from config service.
6.	Config Delivery Channel that captures config logs
7.	SNS topic
8.	SNS subscription with sumologic http source endpoint from step 3
9.	SNS policy that provides access to S3 bucket to perform the publish action on SNS topic.
10.	SumoLogic Collector, source and app information captured and passed further to the SAM app in step 3.

### Setup:
1.	Generate Access key from sumologic console as per docs.
2.	Go to https://serverlessrepo.aws.amazon.com/applications.
3.	Search for sumologic-amazon-config and click on deploy.
4.	In the Configure application parameters panel, enter the following parameters
    - Access ID(Required): Sumo Logic Access ID generated from Step 1
    - Access Key(Required): Sumo Logic Access Key generated from Step 1
    -	Organization ID(Required): Deployment name (environment name in lower case as per docs ) + Org ID (Can be found on your sumologic console under Account overview)
    -	Collector Name: Enter the name of the Hosted Collector which will be created in Sumo Logic.
    -	Source Name: Enter the name of the S3 Source which will be created within the collector.
    -	S3 Bucket Name: Enter the name of S3 Bucket to access logs
    -	Create S3 Bucket: Enter yes if you want to create a bucket. No if you want to use an existing one.
    -	Source Category Name: Enter the name of the Source Category which will be used for writing search queries.
    -	Path Expression: Path Expression to match one or more s3 objects.
 5. Click on Deploy

### License

Apache License 2.0 (Apache-2.0)

## Support

Requests & issues should be filed on GitHub: https://github.com/SumoLogic/sumologic-aws-lambda/issues
