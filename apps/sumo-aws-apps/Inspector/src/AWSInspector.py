
from __future__ import print_function
from crhelper import CfnResource
import boto3
helper = CfnResource(json_logging=False, log_level='DEBUG')
RulePackage={
	"us-west-2": {
	  "CVE": "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-9hgA516p",
	  "CIS": "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-H5hpSawc",
	  "Network": "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-rD1z6dpl",
	  "Security": "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-JJOtZiqQ",
	  "Runtime": "arn:aws:inspector:us-west-2:758058086616:rulespackage/0-vg5GGHSD"
	  },
	"us-east-1": {
	  "CVE": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7",
	  "CIS": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8",
	  "Network": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd",
	  "Security": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q",
	  "Runtime": "arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gBONHN9h"
	  },
	"us-east-2": {
	  "CVE": "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-JnA8Zp85",
	  "CIS": "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-m8r61nnh",
	  "Network": "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-cE4kTR30",
	  "Security": "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-AxKmMHPX",
	  "Runtime": "arn:aws:inspector:us-east-2:646659390643:rulespackage/0-UCYZFKPV"
	  },
	"us-west-1": {
	  "CVE": "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa",
	  "CIS": "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX",
	  "Network": "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF",
	  "Security": "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm",
	  "Runtime": "arn:aws:inspector:us-west-1:166987590008:rulespackage/0-yeYxlt0x"
	  },
	"ap-south-1": {
	  "CVE": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-LqnJE9dO",
	  "CIS": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-PSUlX14m",
	  "Network": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-YxKfjFu1",
	  "Security": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-fs0IZZBj",
	  "Runtime": "arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-EhMQZy6C"
	  },
	"ap-southeast-2":{
	  "CVE": "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-D5TGAxiR",
	  "CIS": "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-Vkd2Vxjq",
	  "Network": "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-FLcuV4Gz",
	  "Security": "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-asL6HRgN",
	  "Runtime": "arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-P8Tel2Xj"
	  },
	"ap-northeast-2": {
	  "CVE": "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-PoGHMznc",
	  "CIS": "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-T9srhg1z",
	  "Network": "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-s3OmLzhL",
	  "Security": "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-2WRpmi4n",
	  "Runtime": "arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-PoYq7lI7"
	  },
	"ap-northeast-1": {
	  "CVE": "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-gHP9oWNT",
	  "CIS": "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-7WNjqgGu",
	  "Network": "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-YI95DVd7",
	  "Security": "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-bBUQnxMq",
	  "Runtime": "arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-knGBhqEu"
	  },
	"eu-west-1": {
	  "CVE": "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-ubA5XvBh",
	  "CIS": "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-sJBhCr0F",
	  "Network": "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SPzU33xe",
	  "Security": "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SnojL3Z6",
	  "Runtime": "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-lLmwe1zd"
	  },
	"eu-central-1": {
	  "CVE": "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-wNqHa8M9",
	  "CIS": "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-nZrAVuv8",
	  "Network": "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-6yunpJ91",
	  "Security": "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-ZujVHEPB",
	  "Runtime": "arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-0GMUM6fg"
	  },
	"us-gov-east-1": {
	  "CVE": "arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-3IFKFuOb",
	  "CIS": "arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-pTLCdIww",
	  "Security": "arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-vlgEGcVD",
	  "Runtime": "arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-850TmCFX"
	  },
	"us-gov-west-1": {
	  "CVE": "arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-4oQgcI4G",
	  "CIS": "arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-Ac4CFOuc",
	  "Security": "arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-rOTGqe5G",
	  "Runtime": "arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-JMyjuzoW"
	  }
}
def handler(event, context):
    helper(event, context)

  
@helper.create
def create(event, context):
    if event['ResourceType'] == "Custom::InspectorAssessmentTemplate":
        AssessmentTargetName = event["ResourceProperties"]["TargetName"]
        AssessmentTemplateName = event["ResourceProperties"]["TemplateName"]
        EnableAllEC2Instances = event["ResourceProperties"]["EnableAllEC2Instances"]
        TopicArn = event["ResourceProperties"]["TopicArn"]
        Tags = event["ResourceProperties"]["Tags"].split(",")
        DurationInSeconds = event["ResourceProperties"]["DurationInSeconds"]
        Region = event["ResourceProperties"]["Region"]
        InstallAmazonInspectorApp = event["ResourceProperties"]["InstallAmazonInspectorApp"]
        data=""
        client = boto3.client('inspector')
        AssessmentTemplateArn =""

        if (InstallAmazonInspectorApp=='Yes'):
            print("Install Amazon Inspector App")
            list_template_response = client.list_assessment_templates(
                filter={
                    'namePattern': AssessmentTemplateName
                },
                maxResults=123
            )
            if(len(list_template_response.get('assessmentTemplateArns')))>0:
                
                AssessmentTemplateArn = list_template_response.get('assessmentTemplateArns')[0]
                print("Amazon Inspector Assessment Template %s already exist" % AssessmentTemplateName)
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_STARTED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_COMPLETED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_STATE_CHANGED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='FINDING_REPORTED',
                    topicArn=TopicArn
                ) 
                print("Added Subscribe for Assessment Template %s" % AssessmentTemplateName)
            else:
                list_target_response = client.list_assessment_targets(
                    filter={
                        'assessmentTargetNamePattern': AssessmentTargetName
                    },
                    maxResults=123
                )
                AssessmentTargetArn = ""
                #print(list_target_response.get('assessmentTargetArns')[0])

                if(len(list_target_response.get('assessmentTargetArns')))>0:
                    AssessmentTargetArn = list_target_response.get('assessmentTargetArns')[0]
                    print("Amazon Inspector Assessment Target %s already exist" % AssessmentTargetName)
                else:
                    print("Create Amazon Inspector Assessment Target %s" % AssessmentTargetName)
                    if (EnableAllEC2Instances=='Yes'):
                        create_target_response = client.create_assessment_target(
                            assessmentTargetName=AssessmentTargetName
                        )
                        AssessmentTargetArn = create_target_response.get('assessmentTargetArn')
                        print("Created Amazon Inspector Assessment Target Arn %s with include all EC2 instances" % AssessmentTargetArn)
                    else:
                        Ec2Tags = []
                        for res in Tags:
                            tag = {'key': res.split('=')[0],'value': res.split('=')[1]}
                            Ec2Tags.append(tag)        

                        create_resource_group_response = client.create_resource_group(
                            resourceGroupTags = Ec2Tags
                        )
                        resourceGroupArn = create_resource_group_response.get('resourceGroupArn')
                        create_target_response = client.create_assessment_target(
                            assessmentTargetName=AssessmentTargetName,
                            resourceGroupArn = resourceGroupArn                                
                        )
                        AssessmentTargetArn = create_target_response.get('assessmentTargetArn')
                        print("Created Amazon Inspector Assessment Target Arn %s with Ec2 tags" % AssessmentTargetArn)

                RulePackages = []
                RulePackages.append(RulePackage.get(Region).get("CVE"))
                RulePackages.append(RulePackage.get(Region).get("CIS"))
                RulePackages.append(RulePackage.get(Region).get("Security"))
                RulePackages.append(RulePackage.get(Region).get("Network"))
                RulePackages.append(RulePackage.get(Region).get("Runtime"))
                print("Created RulePackages %s" % RulePackages)

                create_template_response = client.create_assessment_template(
                    assessmentTargetArn=AssessmentTargetArn,
                    assessmentTemplateName=AssessmentTemplateName,
                    durationInSeconds=int(DurationInSeconds),
                    rulesPackageArns=RulePackages
                )
                AssessmentTemplateArn = create_template_response.get('assessmentTemplateArn')
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_STARTED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_COMPLETED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_STATE_CHANGED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='FINDING_REPORTED',
                    topicArn=TopicArn
                )                                                     
                print("Created Amazon Inspector Assessment Template Arn %s" % AssessmentTemplateArn)
            helper.Status = "SUCCESS" 
            data = {"AssessmentTemplateArn":AssessmentTemplateArn}                   
        else:
            list_template_response = client.list_assessment_templates(
                filter={
                    'namePattern': AssessmentTemplateName
                },
                maxResults=123
            )

            if(len(list_template_response.get('assessmentTemplateArns')))>0:
                AssessmentTemplateArn = list_template_response.get('assessmentTemplateArns')[0]
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_STARTED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_COMPLETED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_STATE_CHANGED',
                    topicArn=TopicArn
                )
                subscribe_response = client.subscribe_to_event(
                    resourceArn= AssessmentTemplateArn,
                    event='FINDING_REPORTED',
                    topicArn=TopicArn
                ) 
                helper.Status = "SUCCESS"     
            else:
                helper.Status = "FAILED"
            data = {"AssessmentTemplateArn":AssessmentTemplateArn}
    helper.Data.update(data)
    return "%s" % (event.get('LogicalResourceId', ''))

@helper.update
def update(event, context):
    print("%s Update" % event.get('PhysicalResourceId'))
    return "%s" % (event.get('LogicalResourceId', ''))
 
@helper.delete
def delete(event, context):
    if event['ResourceType'] == "Custom::InspectorAssessmentTemplate":
        AssessmentTargetName = event["ResourceProperties"]["TargetName"]
        AssessmentTemplateName = event["ResourceProperties"]["TemplateName"]
        TopicArn = event["ResourceProperties"]["TopicArn"]
        RemoveAWSResourcesOnDeleteStack = event["ResourceProperties"]["RemoveAWSResourcesOnDeleteStack"]
        client = boto3.client('inspector')
        data=""
        list_template_response = client.list_assessment_templates(
            filter={
                'namePattern': AssessmentTemplateName
            },
            maxResults=123
        )
        AssessmentTemplateArn=""

        if(len(list_template_response.get('assessmentTemplateArns')))>0:
            AssessmentTemplateArn = list_template_response.get('assessmentTemplateArns')[0]
        list_target_response = client.list_assessment_targets(
            filter={
                'assessmentTargetNamePattern': AssessmentTargetName
            },
            maxResults=123
        )
        AssessmentTargetArn = ""
        if(len(list_target_response.get('assessmentTargetArns')))>0:
            AssessmentTargetArn = list_target_response.get('assessmentTargetArns')[0]

        if (len(AssessmentTemplateArn)>0):         
            if (RemoveAWSResourcesOnDeleteStack == 'false'):
                print("Unsubscribe from event")
                Unsubscribe_response = client.unsubscribe_from_event(
                    resourceArn=AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_STARTED',
                    topicArn = TopicArn
                )
                Unsubscribe_response = client.unsubscribe_from_event(
                    resourceArn=AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_COMPLETED',
                    topicArn = TopicArn
                )
                Unsubscribe_response = client.unsubscribe_from_event(
                    resourceArn=AssessmentTemplateArn,
                    event='ASSESSMENT_RUN_STATE_CHANGED',
                    topicArn = TopicArn
                )
                Unsubscribe_response = client.unsubscribe_from_event(
                    resourceArn=AssessmentTemplateArn,
                    event='FINDING_REPORTED',
                    topicArn = TopicArn
                )                                            
            else:
                print("Delete Assessment Template")
                delete_template_response = client.delete_assessment_template(
                    assessmentTemplateArn=AssessmentTemplateArn
                ) 
                if (len(AssessmentTargetArn)>0):
                    print("Delete Assessment Target")
                    delete_target_response = client.delete_assessment_target(
                        assessmentTargetArn=AssessmentTargetArn
                    )
        else:
            if (RemoveAWSResourcesOnDeleteStack=='true'):
                if (len(AssessmentTargetArn)>0):
                    print("Delete Assessment Target")
                    delete_target_response = client.delete_assessment_target(
                        assessmentTargetArn=AssessmentTargetArn
                    )
    helper.Status = "SUCCESS"
    helper.Data.update(data = {"Result":"OK"})     
    print("%s delete" % event.get('PhysicalResourceId'))
    return "%s" % (event.get('LogicalResourceId', ''))

