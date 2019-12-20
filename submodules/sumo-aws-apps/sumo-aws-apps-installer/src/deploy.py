import boto3
from crhelper import CfnResource
import logging
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.WARNING)
helper = CfnResource(json_logging=False, log_level='DEBUG')
client = boto3.client('serverlessrepo')


def launch_stack(event):
    helper.Status = "SUCCESS"
    props = event.get("ResourceProperties")
    template_params = props.get("Parameters")
    stackname = props.get("StackName")
    response = client.create_cloud_formation_template(
        ApplicationId= props.get("ApplicationId"),
        SemanticVersion= props.get("SemanticVersion")
    )
    template_url = response.get("TemplateUrl")

    cfn = boto3.client('cloudformation')
    current_ts = datetime.now().isoformat().split('.')[0].replace(':','-')
    #stackname = stackname + current_ts
    capabilities = ['CAPABILITY_IAM', 'CAPABILITY_AUTO_EXPAND']
    try:
        stackdata = cfn.create_stack(
          StackName=stackname,
          DisableRollback=False,
          TemplateURL=template_url,
          Parameters=template_params,
          Capabilities=capabilities)
        """
        waiter = cfn.get_waiter('stack_create_complete')
        waiter.wait(

            StackName=stackname,

            WaiterConfig={
                'Delay': 10

            }
        )
        stack_info = cfn.describe_stacks(StackName=stackname)
        stack_status = stack_info['Stacks'][0]['StackStatus']



        print(stack_info['Stacks'])
        """
        helper.Data.update(stackdata)

    except Exception as e:
        helper.Reason = str(e)

    return helper



@helper.create
def create(event, context):

    return launch_stack(event)


@helper.update
def update(event, context):

    return event


@helper.delete
def delete(event, context):
    cfn = boto3.client('cloudformation')
    stackname = event.get("ResourceProperties").get("StackName")
    response = cfn.delete_stack(
        StackName= stackname
        )
    return event


def handler(event, context):
    helper(event, context)


class context(object):
    def get_remaining_time_in_millis(self):
        return 100000

context1 = context();
event =  {
	"ResourceProperties": {
		"ApplicationId": "arn:aws:serverlessrepo:us-west-2:296516481872:applications/sumo-guardduty",
        "SemanticVersion":"0.0.1",
		"Parameters": [{
				"ParameterKey": "SumoAccessID",
				"ParameterValue": "suBtoxGR9wukdw-544456"
			},
			{
				"ParameterKey": "SumoAccessKey",
				"ParameterValue": "WYtXJhYPZlYTnV0bLIbKTfWMeayAetPZnwoCY6KJ3dkoMTvcgboDq6hd1hBQKfx7"
			},
			{
				"ParameterKey": "SumoDeployment",
				"ParameterValue": "us2"
			}
		]



	}
}
#handler(event, context1)
#launch_stack(event)