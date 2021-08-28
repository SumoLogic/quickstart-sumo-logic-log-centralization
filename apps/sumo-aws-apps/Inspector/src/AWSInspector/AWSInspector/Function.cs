using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Amazon.Inspector;
using Amazon.Inspector.Model;
using Amazon.Lambda.Core;
using static AWSInspector.CfnResponse;
using static AWSInspector.ResponseData;

// Assembly attribute to enable the Lambda function's JSON input to be converted into a .NET class.
[assembly: LambdaSerializer(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]

namespace AWSInspector
{
    public class Function
    {
        JObject JsonRulePackageArn = JObject.Parse(
            @"{
	""us-west-2"": {
      ""CVE"": ""arn:aws:inspector:us-west-2:758058086616:rulespackage/0-9hgA516p"",
      ""CIS"": ""arn:aws:inspector:us-west-2:758058086616:rulespackage/0-H5hpSawc"",
      ""Network"": ""arn:aws:inspector:us-west-2:758058086616:rulespackage/0-rD1z6dpl"",
      ""Security"": ""arn:aws:inspector:us-west-2:758058086616:rulespackage/0-JJOtZiqQ"",
      ""Runtime"": ""arn:aws:inspector:us-west-2:758058086616:rulespackage/0-vg5GGHSD""
	  },
    ""us-east-1"": {
      ""CVE"": ""arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gEjTy7T7"",
      ""CIS"": ""arn:aws:inspector:us-east-1:316112463485:rulespackage/0-rExsr2X8"",
      ""Network"": ""arn:aws:inspector:us-east-1:316112463485:rulespackage/0-PmNV0Tcd"",
      ""Security"": ""arn:aws:inspector:us-east-1:316112463485:rulespackage/0-R01qwB5Q"",
      ""Runtime"": ""arn:aws:inspector:us-east-1:316112463485:rulespackage/0-gBONHN9h""
	  },
    ""us-east-2"": {
      ""CVE"": ""arn:aws:inspector:us-east-2:646659390643:rulespackage/0-JnA8Zp85"",
      ""CIS"": ""arn:aws:inspector:us-east-2:646659390643:rulespackage/0-m8r61nnh"",
      ""Network"": ""arn:aws:inspector:us-east-2:646659390643:rulespackage/0-cE4kTR30"",
      ""Security"": ""arn:aws:inspector:us-east-2:646659390643:rulespackage/0-AxKmMHPX"",
      ""Runtime"": ""arn:aws:inspector:us-east-2:646659390643:rulespackage/0-UCYZFKPV""
	  },
    ""us-west-1"": {
      ""CVE"": ""arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TKgzoVOa"",
      ""CIS"": ""arn:aws:inspector:us-west-1:166987590008:rulespackage/0-xUY8iRqX"",
      ""Network"": ""arn:aws:inspector:us-west-1:166987590008:rulespackage/0-TxmXimXF"",
      ""Security"": ""arn:aws:inspector:us-west-1:166987590008:rulespackage/0-byoQRFYm"",
      ""Runtime"": ""arn:aws:inspector:us-west-1:166987590008:rulespackage/0-yeYxlt0x""
	  },
    ""ap-south-1"": {
      ""CVE"": ""arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-LqnJE9dO"",
      ""CIS"": ""arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-PSUlX14m"",
      ""Network"": ""arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-YxKfjFu1"",
      ""Security"": ""arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-fs0IZZBj"",
      ""Runtime"": ""arn:aws:inspector:ap-south-1:162588757376:rulespackage/0-EhMQZy6C""
	  },
    ""ap-southeast-2"":{
      ""CVE"": ""arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-D5TGAxiR"",
      ""CIS"": ""arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-Vkd2Vxjq"",
      ""Network"": ""arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-FLcuV4Gz"",
      ""Security"": ""arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-asL6HRgN"",
      ""Runtime"": ""arn:aws:inspector:ap-southeast-2:454640832652:rulespackage/0-P8Tel2Xj""
	  },
    ""ap-northeast-2"": {
      ""CVE"": ""arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-PoGHMznc"",
      ""CIS"": ""arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-T9srhg1z"",
      ""Network"": ""arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-s3OmLzhL"",
      ""Security"": ""arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-2WRpmi4n"",
      ""Runtime"": ""arn:aws:inspector:ap-northeast-2:526946625049:rulespackage/0-PoYq7lI7""
	  },
    ""ap-northeast-1"": {
      ""CVE"": ""arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-gHP9oWNT"",
      ""CIS"": ""arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-7WNjqgGu"",
      ""Network"": ""arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-YI95DVd7"",
      ""Security"": ""arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-bBUQnxMq"",
      ""Runtime"": ""arn:aws:inspector:ap-northeast-1:406045910587:rulespackage/0-knGBhqEu""
	  },
    ""eu-west-1"": {
      ""CVE"": ""arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-ubA5XvBh"",
      ""CIS"": ""arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-sJBhCr0F"",
      ""Network"": ""arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SPzU33xe"",
      ""Security"": ""arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SnojL3Z6"",
      ""Runtime"": ""arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-lLmwe1zd""
	  },
    ""eu-central-1"": {
      ""CVE"": ""arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-wNqHa8M9"",
      ""CIS"": ""arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-nZrAVuv8"",
      ""Network"": ""arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-6yunpJ91"",
      ""Security"": ""arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-ZujVHEPB"",
      ""Runtime"": ""arn:aws:inspector:eu-central-1:537503971621:rulespackage/0-0GMUM6fg""
	  },
    ""us-gov-east-1"": {
      ""CVE"": ""arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-3IFKFuOb"",
      ""CIS"": ""arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-pTLCdIww"",
      ""Security"": ""arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-vlgEGcVD"",
      ""Runtime"": ""arn:aws-us-gov:inspector:us-gov-east-1:206278770380:rulespackage/0-850TmCFX""
	  },
    ""us-gov-west-1"": {
      ""CVE"": ""arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-4oQgcI4G"",
      ""CIS"": ""arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-Ac4CFOuc"",
      ""Security"": ""arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-rOTGqe5G"",
      ""Runtime"": ""arn:aws-us-gov:inspector:us-gov-west-1:850862329162:rulespackage/0-JMyjuzoW""
	  }
	}");

        static void AddSNS(IAmazonInspector Inspector, string ResourceArn, string TopicArn)
        {
            var ASSESSMENT_RUN_COMPLETED = new SubscribeToEventRequest()
            {
                Event = InspectorEvent.ASSESSMENT_RUN_COMPLETED,
                ResourceArn = ResourceArn,
                TopicArn = TopicArn
            };
            var ASSESSMENT_RUN_STARTED = new SubscribeToEventRequest()
            {
                Event = InspectorEvent.ASSESSMENT_RUN_STARTED,
                ResourceArn = ResourceArn,
                TopicArn = TopicArn
            };
            var ASSESSMENT_RUN_STATE_CHANGED = new SubscribeToEventRequest()
            {
                Event = InspectorEvent.ASSESSMENT_RUN_STATE_CHANGED,
                ResourceArn = ResourceArn,
                TopicArn = TopicArn
            };
            var FINDING_REPORTED = new SubscribeToEventRequest()
            {
                Event = InspectorEvent.FINDING_REPORTED,
                ResourceArn = ResourceArn,
                TopicArn = TopicArn
            };
            var RES_ASSESSMENT_RUN_COMPLETED = Inspector.SubscribeToEventAsync(ASSESSMENT_RUN_COMPLETED);
            var RES_ASSESSMENT_RUN_STARTED = Inspector.SubscribeToEventAsync(ASSESSMENT_RUN_STARTED);
            var RES_ASSESSMENT_RUN_STATE_CHANGED = Inspector.SubscribeToEventAsync(ASSESSMENT_RUN_STATE_CHANGED);
            var RES_ASSESSMENT_FINDING_REPORTED = Inspector.SubscribeToEventAsync(FINDING_REPORTED);

            Task.WaitAll(RES_ASSESSMENT_RUN_COMPLETED, RES_ASSESSMENT_RUN_STARTED, RES_ASSESSMENT_RUN_STATE_CHANGED, RES_ASSESSMENT_FINDING_REPORTED);
        }

        public string Handler(JObject input, ILambdaContext context)
        {
            string result = "";
            CfnResponse cfn = new CfnResponse();
            switch (input["RequestType"].ToString())
            {
                case RequestType_Create:
                    switch (input["ResourceType"].ToString())
                    {
                        case "Custom::InspectorAssessmentTemplate":
                            string AssessmentTargetName = input["ResourceProperties"]["TargetName"].ToString();
                            string AssessmentTemplateName = input["ResourceProperties"]["TemplateName"].ToString();
                            bool EnableAllEC2Instances = input["ResourceProperties"]["EnableAllEC2Instances"].ToString().Equals("No");
                            string TopicArn = input["ResourceProperties"]["TopicArn"].ToString();
                            string[] Tags = input["ResourceProperties"]["Tags"].ToString().Split(",");
                            int DurationInSeconds = int.Parse(input["ResourceProperties"]["DurationInSeconds"].ToString());
                            string Region = input["ResourceProperties"]["Region"].ToString();
                            bool InstallAmazonInspectorApp = input["ResourceProperties"]["InstallAmazonInspectorApp"].ToString().Equals("Yes");
                            var Inspector = new AmazonInspectorClient();                           
                            try
                            {
                                if (InstallAmazonInspectorApp)
                                {
                                    AssessmentTemplateFilter Filter_Template = new AssessmentTemplateFilter()
                                    {
                                        NamePattern = AssessmentTemplateName
                                    };
                                    var response_template = Inspector.ListAssessmentTemplatesAsync(new ListAssessmentTemplatesRequest()
                                    {
                                        Filter = Filter_Template
                                    });
                                    Task.WaitAll(response_template);
                                    string AssessmentTemplateArn = "";
                                    if (response_template.Result.AssessmentTemplateArns.Count() > 0)
                                    {
                                        // If you already have an AssessmentTemplate, just add SNS to the AssessmentTemplate
                                        AddSNS(Inspector, response_template.Result.AssessmentTemplateArns[0].ToString(), TopicArn);
                                        AssessmentTemplateArn = response_template.Result.AssessmentTemplateArns[0].ToString();
                                    }
                                    else
                                    {
                                        //If there is no AssessmentTemplate. start checking AssessmentTarget exists
                                        AssessmentTargetFilter Filter_Target = new AssessmentTargetFilter()
                                        {
                                            AssessmentTargetNamePattern = AssessmentTargetName
                                        };
                                        var response_target = Inspector.ListAssessmentTargetsAsync(new ListAssessmentTargetsRequest()
                                        {
                                            Filter = Filter_Target
                                        });
                                        Task.WaitAll(response_target);
                                        string AssessmentTargetArn = "";

                                        if (response_target.Result.AssessmentTargetArns.Count() > 0)
                                        {
                                            //If already have an AssessmentTarget. get AssessmentTargetArns
                                            AssessmentTargetArn = response_target.Result.AssessmentTargetArns[0].ToString();
                                        }
                                        else
                                        {
                                            //If there is no AssessmentTarget. start create AssessmentTarget
                                            CreateAssessmentTargetRequest TargetRequest = new CreateAssessmentTargetRequest();
                                            if (EnableAllEC2Instances)
                                            {
                                                //If AssessmentTarget use Tags for Ec2 . Create ResourceGroupTag
                                                List<ResourceGroupTag> GroupTags = new List<ResourceGroupTag>();
                                                foreach (string Tag in Tags)
                                                {
                                                    string[] arr = Tag.Split("=");
                                                    GroupTags.Add(new ResourceGroupTag()
                                                    {
                                                        Key = arr[0].ToString(),
                                                        Value = arr[1].ToString()
                                                    });
                                                }
                                                var Res_Create_ResourceGroup = Inspector.CreateResourceGroupAsync(new CreateResourceGroupRequest
                                                {
                                                    ResourceGroupTags = GroupTags,
                                                });
                                                Task.WaitAll(Res_Create_ResourceGroup);
                                                TargetRequest.AssessmentTargetName = AssessmentTargetName;
                                                TargetRequest.ResourceGroupArn = Res_Create_ResourceGroup.Result.ResourceGroupArn;
                                            }
                                            else
                                            {
                                                //If AssessmentTarget use For All Ec2 . Create ResourceGroupTag
                                                TargetRequest.AssessmentTargetName = AssessmentTargetName;
                                            }
                                            var create_target = Inspector.CreateAssessmentTargetAsync(TargetRequest);
                                            Task.WaitAll(create_target);
                                            AssessmentTargetArn = create_target.Result.AssessmentTargetArn;
                                        }
                                        //###################################### END Assessment Target ######################################

                                        List<string> RulesPackageArns = new List<string>
                                {
                                    JsonRulePackageArn[Region]["CVE"].ToString(),
                                    JsonRulePackageArn[Region]["CIS"].ToString(),
                                    JsonRulePackageArn[Region]["Network"].ToString(),
                                    JsonRulePackageArn[Region]["Security"].ToString(),
                                    JsonRulePackageArn[Region]["Runtime"].ToString()
                                };
                                        var create_teamplate = Inspector.CreateAssessmentTemplateAsync(new CreateAssessmentTemplateRequest()
                                        {
                                            AssessmentTemplateName = AssessmentTemplateName,
                                            AssessmentTargetArn = AssessmentTargetArn,
                                            DurationInSeconds = DurationInSeconds,
                                            RulesPackageArns = RulesPackageArns
                                        });
                                        Task.WaitAll(create_teamplate);
                                        AssessmentTemplateArn = create_teamplate.Result.AssessmentTemplateArn;
                                    }
                                    AddSNS(Inspector, AssessmentTemplateArn, TopicArn);
                                    result = cfn.Send(input, context, OpsStatus.Success, new ResponseData()
                                    {
                                        Result = AssessmentTemplateArn
                                    });
                                }
                                else
                                {
                                    AssessmentTemplateFilter Filter_Template = new AssessmentTemplateFilter()
                                    {
                                        NamePattern = AssessmentTemplateName
                                    };
                                    var response_template = Inspector.ListAssessmentTemplatesAsync(new ListAssessmentTemplatesRequest()
                                    {
                                        Filter = Filter_Template
                                    });
                                    Task.WaitAll(response_template);
                                    string AssessmentTemplateArn = "";
                                    if (response_template.Result.AssessmentTemplateArns.Count() > 0)
                                    {
                                        // If you already have an AssessmentTemplate, just add SNS to the AssessmentTemplate
                                        AddSNS(Inspector, response_template.Result.AssessmentTemplateArns[0].ToString(), TopicArn);
                                        AssessmentTemplateArn = response_template.Result.AssessmentTemplateArns[0].ToString();
                                        result = cfn.Send(input, context, OpsStatus.Success, new ResponseData()
                                        {
                                            Result = AssessmentTemplateArn
                                        });
                                    }
                                    else
                                    {
                                        result = cfn.Send(input, context, OpsStatus.Fail, "Error: " + AssessmentTemplateName + " don't exist", new ResponseData()
                                        {
                                            Result = "Error"
                                        });
                                    }
                                }    
                                
                            }
                            catch (Exception ex)
                            {
                                result = cfn.Send(input, context, OpsStatus.Fail, "Error: " + ex.Message,  new ResponseData()
                                {
                                    Result = "Error"
                                });
                                return result;
                            }
                            return result;
                        default:
                            break;
                    }
                    break;
                case RequestType_Delete:
                    switch (input["ResourceType"].ToString())
                    {
                        case "Custom::InspectorAssessmentTemplate":
                            string AssessmentTargetName = input["ResourceProperties"]["TargetName"].ToString();
                            string AssessmentTemplateName = input["ResourceProperties"]["TemplateName"].ToString();
                            bool RemoveAWSResourcesOnDeleteStack = input["ResourceProperties"]["RemoveAWSResourcesOnDeleteStack"].ToString().Equals("true");
                            try
                            {
                                if (RemoveAWSResourcesOnDeleteStack)
                                {

                                    var Inspector = new AmazonInspectorClient();
                                    AssessmentTemplateFilter Filter_Template = new AssessmentTemplateFilter()
                                    {
                                        NamePattern = AssessmentTemplateName
                                    };
                                    var response_template = Inspector.ListAssessmentTemplatesAsync(new ListAssessmentTemplatesRequest()
                                    {
                                        Filter = Filter_Template
                                    });
                                    Task.WaitAll(response_template);

                                    foreach (string AssessmentTemplateArn in response_template.Result.AssessmentTemplateArns)
                                    {
                                        var response_delete_template = Inspector.DeleteAssessmentTemplateAsync(new DeleteAssessmentTemplateRequest()
                                        {
                                            AssessmentTemplateArn = AssessmentTemplateArn
                                        });
                                        Task.WaitAll(response_delete_template);
                                    }

                                    AssessmentTargetFilter Filter_Target = new AssessmentTargetFilter()
                                    {
                                        AssessmentTargetNamePattern = AssessmentTargetName
                                    };
                                    var response_target = Inspector.ListAssessmentTargetsAsync(new ListAssessmentTargetsRequest()
                                    {
                                        Filter = Filter_Target
                                    });
                                    Task.WaitAll(response_target);

                                    foreach (string AssessmentTargetArn in response_target.Result.AssessmentTargetArns)
                                    {
                                        var response_delete_target = Inspector.DeleteAssessmentTargetAsync(new DeleteAssessmentTargetRequest()
                                        {
                                            AssessmentTargetArn = AssessmentTargetArn
                                        });
                                        Task.WaitAll(response_delete_target);
                                    }
                                }
                                result = cfn.Send(input, context, OpsStatus.Success, new ResponseData()
                                {
                                    Result = "Remove Inspector OK"
                                });
                            }
                            catch(Exception ex)
                            {
                                result = cfn.Send(input, context, OpsStatus.Fail, "Error: " + ex.Message.ToString(), new ResponseData()
                                {
                                    Result = "Error"
                                });
                            }
                           
                            break;
                        default:
                            break;
                    }
                    return result;
                default:
                    break;
            }
            return "OK";
        }
    }
}
