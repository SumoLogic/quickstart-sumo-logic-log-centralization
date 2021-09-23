import json
import os
import re
import time
import logging
from abc import abstractmethod

import boto3
import six
from botocore.exceptions import ClientError
from resourcefactory import AutoRegisterResource
from retrying import retry
from botocore.config import Config
from time import time as now
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup Default Logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


@six.add_metaclass(AutoRegisterResource)
class AWSResource(object):

    @abstractmethod
    def create(self, *args, **kwargs):
        pass

    @abstractmethod
    def update(self, *args, **kwargs):
        pass

    @abstractmethod
    def delete(self, *args, **kwargs):
        pass

    @abstractmethod
    def extract_params(self, event):
        pass

class GuardDuty(AWSResource):

    def __init__(self, props,  *args, **kwargs):

        self.CLOUDFORMATION_PARAMETERS = ["AUTO_ENABLE_S3_LOGS", "AWS_PARTITION", "CONFIGURATION_ROLE_NAME",
                                    "DELEGATED_ADMIN_ACCOUNT_ID", "DELETE_DETECTOR_ROLE_NAME", "ENABLED_REGIONS",
                                    "FINDING_PUBLISHING_FREQUENCY", "KMS_KEY_ARN", "PUBLISHING_DESTINATION_BUCKET_ARN"]
        self.SERVICE_ROLE_NAME = "AWSServiceRoleForAmazonGuardDuty"
        self.SERVICE_NAME = "guardduty.amazonaws.com"
        self.PAGE_SIZE = 20  # Max page size for list_accounts
        self.MAX_RUN_COUNT = 18  # 3 minute wait = 18 x 10 seconds
        self.SLEEP_SECONDS = 10
        self.MAX_THREADS = 10
        self.STS_CLIENT = boto3.client('sts')

    def get_service_client(self,aws_service: str, aws_region: str, session=None):
        if aws_region:
            if session:
                service_client = session.client(aws_service, region_name=aws_region)
            else:
                service_client = boto3.client(aws_service, aws_region)
        else:
            if session:
                service_client = session.client(aws_service)
            else:
                service_client = boto3.client(aws_service)
        return service_client

    def is_region_available(self,region):
        regional_sts = boto3.client('sts', region_name=region)
        try:
            regional_sts.get_caller_identity()
            return True
        except ClientError as error:
            if "InvalidClientTokenId" in str(error):
                logger.info(f"Region: {region} is not available")
                return False
            else:
                logger.error(f"{error}")
                
    def get_available_service_regions(self, user_regions: str, aws_service: str) -> list:
        available_regions = []
        try:
            if user_regions.strip():
                logger.info(f"USER REGIONS: {str(user_regions)}")
                service_regions = [value.strip() for value in user_regions.split(",") if value != '']
            else:
                service_regions = boto3.session.Session().get_available_regions(
                    aws_service
                )
            logger.info(f"SERVICE REGIONS: {service_regions}")
        except ClientError as ce:
            logger.error(f"get_available_service_regions error: {ce}")
            raise ValueError("Error getting service regions")

        for region in service_regions:
            if self.is_region_available(region):
                available_regions.append(region)

        logger.info(f"AVAILABLE REGIONS: {available_regions}")
        return available_regions

    def get_all_organization_accounts(self,exclude_account_id: str):
        accounts = []  # used for create_members
        account_ids = []  # used for disassociate_members

        try:
            organizations = boto3.client("organizations")
            paginator = organizations.get_paginator("list_accounts")

            for page in paginator.paginate(PaginationConfig={"PageSize": self.PAGE_SIZE}):
                for acct in page["Accounts"]:
                    if exclude_account_id and acct["Id"] not in exclude_account_id:
                        if acct["Status"] == "ACTIVE":  # Store active accounts in a dict
                            account_record = {"AccountId": acct["Id"], "Email": acct["Email"]}
                            accounts.append(account_record)
                            account_ids.append(acct["Id"])
        except Exception as exc:
            logger.error(f"get_all_organization_accounts error: {exc}")
            raise ValueError("Error error getting accounts")

        return accounts, account_ids

    def assume_role(self,aws_account_number: str, aws_partition: str, role_name: str, session_name: str):
        try:
            response = self.STS_CLIENT.assume_role(
                RoleArn=f"arn:{aws_partition}:iam::{aws_account_number}:role/{role_name}",
                RoleSessionName=session_name,
            )
            # Storing STS credentials
            session = boto3.Session(
                aws_access_key_id=response["Credentials"]["AccessKeyId"],
                aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
                aws_session_token=response["Credentials"]["SessionToken"],
            )
            logger.debug(f"Assumed session for {aws_account_number}")

            return session
        except Exception as exc:
            logger.error(f"Unexpected error: {exc}")
            raise ValueError("Error assuming role")

    def gd_create_members(self,guardduty_client, detector_id: str, accounts: list):
        try:
            logger.info("Creating members")
            create_members_response = guardduty_client.create_members(DetectorId=detector_id, AccountDetails=accounts)

            if "UnprocessedAccounts" in create_members_response and create_members_response["UnprocessedAccounts"]:
                unprocessed = True
                retry_count = 0
                unprocessed_accounts = []
                while unprocessed:
                    retry_count += 1
                    logger.info(f"Unprocessed Accounts: {create_members_response['UnprocessedAccounts']}")
                    remaining_accounts = []

                    for unprocessed_account in create_members_response["UnprocessedAccounts"]:
                        account_id = unprocessed_account["AccountId"]
                        account_info = [account_record for account_record in accounts if
                                        account_record["AccountId"] == account_id]
                        remaining_accounts.append(account_info[0])

                    if remaining_accounts:
                        create_members_response = guardduty_client.create_members(DetectorId=detector_id,
                                                                                AccountDetails=remaining_accounts)
                        if "UnprocessedAccounts" in create_members_response \
                                and create_members_response["UnprocessedAccounts"]:
                            unprocessed_accounts = create_members_response["UnprocessedAccounts"]
                            if retry_count == 2:
                                unprocessed = False
                        else:
                            unprocessed = False

                if unprocessed_accounts:
                    logger.info(f"Unprocessed Member Accounts: {unprocessed_accounts}")
                    raise ValueError(f"Unprocessed Member Accounts")
        except Exception as exc:
            logger.error(f"{exc}")
            raise ValueError(f"Error Creating Member Accounts")

    def update_member_detectors(self,guardduty_client, detector_id: str, account_ids: list):
        try:
            configuration_params = {
                "DetectorId": detector_id,
                "AccountIds": account_ids,
                "DataSources": {"S3Logs": {"Enable": True}}
            }
            update_member_response = guardduty_client.update_member_detectors(**configuration_params)

            if "UnprocessedAccounts" in update_member_response and update_member_response["UnprocessedAccounts"]:
                unprocessed = True
                retry_count = 0
                unprocessed_accounts = []
                while unprocessed:
                    time.sleep(self.SLEEP_SECONDS)
                    retry_count += 1
                    remaining_accounts = []

                    for unprocessed_account in update_member_response["UnprocessedAccounts"]:
                        if unprocessed_account["AccountId"] in account_ids:
                            remaining_accounts.append(unprocessed_account["AccountId"])

                    if remaining_accounts:
                        configuration_params["AccountIds"] = remaining_accounts
                        update_member_response = guardduty_client.update_member_detectors(**configuration_params)
                        if "UnprocessedAccounts" in update_member_response \
                                and update_member_response["UnprocessedAccounts"]:
                            unprocessed_accounts = update_member_response["UnprocessedAccounts"]
                            if retry_count == 2:
                                unprocessed = False
                        else:
                            unprocessed = False

                if unprocessed_accounts:
                    logger.info(f"Update Member Detectors Unprocessed Member Accounts: {unprocessed_accounts}")
                    raise ValueError(f"Unprocessed Member Accounts")
        except Exception as error:
            logger.error(f"update member detectors error: {error}")
            raise ValueError("Error updating member detectors")

    def update_guardduty_configuration(self,guardduty_client, auto_enable_s3_logs: bool, detector_id: str,
                                    finding_publishing_frequency: str, account_ids: list):
        try:
            org_configuration_params = {"DetectorId": detector_id, "AutoEnable": True}
            admin_configuration_params = {
                "DetectorId": detector_id,
                "FindingPublishingFrequency": finding_publishing_frequency
            }

            if auto_enable_s3_logs:
                org_configuration_params["DataSources"] = {"S3Logs": {"AutoEnable": True}}
                admin_configuration_params["DataSources"] = {"S3Logs": {"Enable": True}}

            guardduty_client.update_organization_configuration(**org_configuration_params)
            guardduty_client.update_detector(**admin_configuration_params)
            self.update_member_detectors(guardduty_client, detector_id, account_ids)
        except ClientError as error:
            logger.error(f"update_guardduty_configuration {error}")
            raise ValueError(f"Error updating GuardDuty configuration")

    def configure_guardduty(self, session, delegated_account_id: str, auto_enable_s3_logs: bool, available_regions: list,
                            finding_publishing_frequency: str, kms_key_arn: str, publishing_destination_arn: str):

        accounts, account_ids = self.get_all_organization_accounts(delegated_account_id)

        # Loop through the regions and enable GuardDuty
        for region in available_regions:
            try:
                regional_guardduty = self.get_service_client("guardduty", region, session)
                detectors = regional_guardduty.list_detectors()

                if detectors["DetectorIds"]:
                    detector_id = detectors["DetectorIds"][0]
                    logger.info(f"DetectorID: {detector_id} Region: {region}")

                    # Update Publish Destination
                    destinations = regional_guardduty.list_publishing_destinations(DetectorId=detector_id)

                    if "Destinations" in destinations and len(destinations["Destinations"]) == 1:
                        destination_id = destinations["Destinations"][0]["DestinationId"]

                        regional_guardduty.update_publishing_destination(
                            DetectorId=detector_id,
                            DestinationId=destination_id,
                            DestinationProperties={
                                "DestinationArn": publishing_destination_arn,
                                "KmsKeyArn": kms_key_arn,
                            },
                        )
                    else:
                        # Create Publish Destination
                        regional_guardduty.create_publishing_destination(
                            DetectorId=detector_id,
                            DestinationType="S3",
                            DestinationProperties={
                                "DestinationArn": publishing_destination_arn,
                                "KmsKeyArn": kms_key_arn,
                            },
                        )

                    # Create members for existing Organization accounts
                    logger.info(f"Members created for existing accounts: {accounts} in {region}")
                    self.gd_create_members(regional_guardduty, detector_id, accounts)
                    logger.info(f"Waiting {self.SLEEP_SECONDS} seconds")
                    time.sleep(self.SLEEP_SECONDS)
                    self.update_guardduty_configuration(regional_guardduty, auto_enable_s3_logs, detector_id,
                                                finding_publishing_frequency, account_ids)
            except Exception as exc:
                logger.error(f"configure_guardduty Exception: {exc}")
                raise ValueError(f"Configure GuardDuty Exception. Review logs for details.")

    def create_service_linked_role(self,role_name: str, service_name: str):
        iam = boto3.client("iam")
        try:
            iam.get_role(RoleName=role_name)
            service_role_exists = True
        except iam.exceptions.NoSuchEntityException:
            service_role_exists = False
            logger.info(f"{role_name} does not exist")
        except Exception as exc:
            logger.error(f"IAM Get Role Exception: {exc}")
            raise ValueError(f"IAM API Exception. Review logs for details.")

        if not service_role_exists:
            try:
                iam.create_service_linked_role(AWSServiceName=service_name)
            except Exception as exc:
                logger.error(f"IAM Create Service Linked Role Exception: {exc}")
                raise ValueError(f"IAM API Exception. Review logs for details.")

    def check_for_detectors(self, session, available_regions: list) -> bool:
        detectors_exist = False

        for region in available_regions:
            try:
                guardduty = self.get_service_client("guardduty", region, session)
                paginator = guardduty.get_paginator("list_detectors")

                for page in paginator.paginate():
                    if "DetectorIds" in page and page["DetectorIds"]:
                        detectors_exist = True
                    else:
                        detectors_exist = False
                        logger.info(f"Detector Does Not Exist in {region}")
            except self.botocore.exceptions.ClientError as ce:
                if "AccessDeniedException" in str(ce):
                    logger.debug(f"Detector not found in {region}")
                    detectors_exist = False
                    break
                else:
                    logger.info(f"Unexpected Client Exception for {region}: {ce}")
            except Exception as exc:
                logger.error(f"GuardDuty Exception {region}: {exc}")
                raise ValueError(f"GuardDuty API Exception: {exc}")

        return detectors_exist


    def get_associated_members(self, guardduty, detector_id):
        account_ids = []

        try:
            paginator = guardduty.get_paginator("list_members")

            for page in paginator.paginate(DetectorId=detector_id, OnlyAssociated="false",
                                        PaginationConfig={"PageSize": 20}):
                for member in page["Members"]:
                    account_ids.append(member["AccountId"])
        except ClientError as ce:
            logger.error(f"get_associated_members error: {str(ce)}")
            raise ValueError("Error getting associated members")

        return account_ids


    def enable_organization_admin_account(self, admin_account_id: str, available_regions: list):

        # Loop through the regions and enable GuardDuty
        for region in available_regions:
            try:
                guardduty = self.get_service_client("guardduty", region)
                response = guardduty.list_organization_admin_accounts()

                if not response["AdminAccounts"]:
                    enable_admin_account = True
                    logger.info(f"GuardDuty delegated admin {admin_account_id} enabled in {region}")
                else:
                    admin_account = [admin_account for admin_account in response["AdminAccounts"]
                                    if admin_account["AdminAccountId"] == admin_account_id]
                    if admin_account:
                        enable_admin_account = False
                        logger.info(f"GuardDuty delegated admin {admin_account_id} already enabled in {region}")
                    else:
                        enable_admin_account = True

                if enable_admin_account:
                    guardduty.enable_organization_admin_account(AdminAccountId=admin_account_id)

            except Exception as error:
                logger.error(f"GuardDuty Exception {region}: {error}")
                raise ValueError(f"GuardDuty API Exception. Review logs for details.")


    def disable_organization_admin_account(self, regional_guardduty, region: str):
        try:
            response = regional_guardduty.list_organization_admin_accounts()
            if "AdminAccounts" in response and response["AdminAccounts"]:
                for admin_account in response["AdminAccounts"]:
                    admin_account_id = admin_account["AdminAccountId"]
                    if admin_account["AdminStatus"] == "ENABLED":
                        regional_guardduty.disable_organization_admin_account(AdminAccountId=admin_account_id)
                        logger.info(f"GuardDuty Admin Account {admin_account_id} Disabled in {region}")
            else:
                logger.info(f"No GuardDuty Admin Accounts in {region}")
        except ClientError as error:
            logger.error(f"disable_organization_admin_account ClientError: {error}")
            raise ValueError(f"Error disabling admin account in {region}")

    def delete_detectors(self, guardduty_client, region: str, is_delegated_admin: bool = False):
        try:
            detectors = guardduty_client.list_detectors()

            if detectors["DetectorIds"]:
                for detector_id in detectors["DetectorIds"]:
                    if is_delegated_admin:
                        account_ids = self.get_associated_members(guardduty_client, detector_id)
                        logger.info(f"Account IDs: {account_ids}")

                        if account_ids:
                            guardduty_client.disassociate_members(DetectorId=detector_id, AccountIds=account_ids)
                            logger.info(f"GuardDuty accounts disassociated in {region}")

                            guardduty_client.delete_members(DetectorId=detector_id, AccountIds=account_ids)
                            logger.info(f"GuardDuty members deleted in {region}")

                    guardduty_client.delete_detector(DetectorId=detector_id)
        except ClientError as error:
            logger.error(f"delete_detectors ClientError: {error}")
            raise ValueError(f"Error deleting the detector in {region}")


    def cleanup_member_account(self, account_id: str, aws_partition: str, delete_detector_role_name: str,
                            available_regions: list):
        try:
            session = self.assume_role(
                account_id,
                aws_partition,
                delete_detector_role_name,
                "DeleteGuardDuty"
            )

            for region in available_regions:
                try:
                    logger.info(f"Deleting GuardDuty detector in {account_id} {region}")
                    session_guardduty = self.get_service_client("guardduty", region, session)
                    self.delete_detectors(session_guardduty, region, False)
                except Exception as exc:
                    logger.error(f"Error deleting GuardDuty detector in {account_id} {region} Exception: {exc}")
                    raise ValueError(f"Error deleting GuardDuty detector in {account_id} {region}")
        except Exception as exc:
            logger.error(f"Unable to assume {delete_detector_role_name} in {account_id} {exc}")


    def deregister_delegated_administrator(self, delegated_admin_account_id: str,
                                        service_principal: str = "guardduty.amazonaws.com"):
        try:
            logger.info(f"Deregistering the delegated admin {delegated_admin_account_id} for {service_principal}")
            organizations_client = self.get_service_client("organizations", "")
            organizations_client.deregister_delegated_administrator(
                AccountId=delegated_admin_account_id,
                ServicePrincipal=service_principal
            )
        except organizations_client.exceptions.AccountNotRegisteredException as error:
            logger.debug(f"Account is not a registered delegated administrator: {error}")
        except Exception as error:
            logger.error(f"Error deregister_delegated_administrator: {error}")
        #    raise ValueError("Error during deregister delegated administrator")

    def create(self, params, *args, **kwargs):

        try:
            # Required to enable GuardDuty in the Org Management account from the delegated admin
            self.create_service_linked_role(self.SERVICE_ROLE_NAME, self.SERVICE_NAME)

            available_regions = self.get_available_service_regions(params.get("ENABLED_REGIONS", ""), "guardduty")

            self.enable_organization_admin_account(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), available_regions)
            session = self.assume_role(
                params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
                params.get("AWS_PARTITION", "aws"),
                params.get("CONFIGURATION_ROLE_NAME", ""),
                "CreateGuardDuty"
            )
            detectors_exist = False
            run_count = 0

            while not detectors_exist and run_count < self.MAX_RUN_COUNT:
                run_count += 1
                detectors_exist = self.check_for_detectors(session, available_regions)
                logger.info(f"All Detectors Exist: {detectors_exist} Count: {run_count}")
                if not detectors_exist:
                    time.sleep(self.SLEEP_SECONDS)

            if detectors_exist:
                auto_enable_s3_logs = (params.get("AUTO_ENABLE_S3_LOGS", "false")).lower() in "true"
                self.configure_guardduty(
                    session,
                    params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
                    auto_enable_s3_logs,
                    available_regions,
                    params.get("FINDING_PUBLISHING_FREQUENCY", "FIFTEEN_MINUTES"),
                    params.get("KMS_KEY_ARN", ""),
                    params.get("PUBLISHING_DESTINATION_BUCKET_ARN", "")
                )
            else:
                raise ValueError(
                    "GuardDuty Detectors did not get created in the allowed time. "
                    "Check the Org Management delegated admin setup."
                )
        except Exception as exc:
            logger.error(f"Unexpected error {exc}")
            raise ValueError("Unexpected error. Review logs for details.")
        return {'GuardDutyResourceId': "GuardDutyResourceId"}, "GuardDutyResourceId"

    def update(self, params, *args, **kwargs):
        self.create(self, params, *args, **kwargs)

    def delete(self, params, *args, **kwargs):
        """
        CloudFormation Delete Event.
        :param event: event data
        :param context: runtime information
        :return: CloudFormation response
        """
        logger.info("Delete Event")
        try:
            available_regions = self.get_available_service_regions(params.get("ENABLED_REGIONS", ""), "guardduty")
            session = self.assume_role(
                params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
                params.get("AWS_PARTITION", "aws"),
                params.get("CONFIGURATION_ROLE_NAME", ""),
                "DeleteGuardDuty")
            # Loop through the regions and disable GuardDuty in the delegated admin account
            for region in available_regions:
                try:
                    regional_guardduty = self.get_service_client("guardduty", region)
                    self.disable_organization_admin_account(regional_guardduty, region)

                    # Delete Detectors in the Delegated Admin Account
                    session_guardduty = self.get_service_client("guardduty", region, session)
                    self.delete_detectors(session_guardduty, region, True)
                except Exception as exc:
                    logger.error(f"GuardDuty Exception: {exc}")
                    raise ValueError(f"GuardDuty API Exception: {exc}")

            self.deregister_delegated_administrator(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""), self.SERVICE_NAME)
            accounts, account_ids = self.get_all_organization_accounts(params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""))

            # Cleanup member account GuardDuty detectors
            start = now()
            processes = []
            with ThreadPoolExecutor(max_workers=self.MAX_THREADS) as executor:
                for account_id in account_ids:
                    try:
                        processes.append(executor.submit(
                            self.cleanup_member_account,
                            account_id,
                            params.get("AWS_PARTITION", "aws"),
                            params.get("DELETE_DETECTOR_ROLE_NAME", ""),
                            available_regions
                        ))
                    except Exception as error:
                        logger.error(f"{error}")
                        continue
            for task in as_completed(processes):
                logger.info(f"process task - {task.result()}")

            logger.info(f"Time taken to delete member account detectors: {now() - start}")
        except Exception as exc:
            logger.error(f"Unexpected error {exc}")
            raise ValueError("Unexpected error. Review logs for details.")

    def extract_params(self, event):
        props = event.get("ResourceProperties")
        return {
            "params": props
        }                                                                                 

class AWSARN(AWSResource):


    def __init__(self, props,  *args, **kwargs):
        #self.region = os.environ.get("AWS_REGION", "us-east-1")
        self.stscli = boto3.client('sts')

    def create(self, params, *args, **kwargs):
        print(params)
        remote_accountid = params['accountID']
        remote_role = params['roleName']
        role_arn = "arn:aws:iam::"+ remote_accountid + ":role/"+remote_role
        region_remote = params['region']
        stack_name = params['stackName']
        output_key = params['outputKey']
        acct_b = self.stscli.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="cross_acct_lambda"
        )
        ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
        SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
        SESSION_TOKEN = acct_b['Credentials']['SessionToken']

        my_config = Config(
            region_name = region_remote,
            signature_version = 'v4',
            retries = {
                'max_attempts': 10,
                'mode': 'standard'
            }
        )

        client_b = boto3.client(
            'cloudformation',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
            config=my_config
        )
        response = client_b.list_stacks(
            StackStatusFilter=[
        'CREATE_COMPLETE']
        )
        all_stacks = response['StackSummaries']
        print("all_stacks:")
        print(all_stacks)
        stack_results = []
        for stack in all_stacks:
            if stack_name in stack['StackName']:
                stack_results.append(stack)
        first_stack = stack_results[0]
        response_describe_stacks = client_b.describe_stacks(
            StackName=first_stack['StackName']
        )
        print("stack_results:")
        print(stack_results)
        outputs_response = response_describe_stacks['Stacks'][0]['Outputs']
        value_arn = ""
        for op in outputs_response:
            if op['OutputKey'] == output_key:
                value_arn = op['OutputValue']
                break
        return {'ARN': value_arn}, value_arn
        

    def update(self, params, *args, **kwargs):
        pass

    def delete(self, *args, **kwargs):
        pass

    def extract_params(self, event):
        props = event.get("ResourceProperties")
        return {
            "params": props
        }

class AWSTrail(AWSResource):
    boolean_params = ["IncludeGlobalServiceEvents", "IsMultiRegionTrail", "EnableLogFileValidation",
                      "IsOrganizationTrail"]

    def __init__(self, props, *args, **kwargs):
        self.region = os.environ.get("AWS_REGION", "us-east-1")
        self.cloudtrailcli = boto3.client('cloudtrail', region_name=self.region)

    def create(self, trail_name, params, *args, **kwargs):
        try:
            response = self.cloudtrailcli.create_trail(**params)
            print("Trail created %s" % trail_name)
            self.cloudtrailcli.start_logging(Name=trail_name)
            return {"TrailArn": response["TrailARN"]}, response["TrailARN"]
        except ClientError as e:
            print("Error in creating trail %s" % e.response['Error'])
            raise
        except Exception as e:
            print("Error in creating trail %s" % e)
            raise

    def update(self, trail_name, params, *args, **kwargs):
        try:
            response = self.cloudtrailcli.update_trail(**params)
            print("Trail updated %s" % trail_name)
            self.cloudtrailcli.start_logging(Name=trail_name)
            return {"TrailArn": response["TrailARN"]}, response["TrailARN"]
        except ClientError as e:
            print("Error in updating trail %s" % e.response['Error'])
            raise
        except Exception as e:
            print("Error in updating trail %s" % e)
            raise

    def delete(self, trail_name, *args, **kwargs):
        try:
            self.cloudtrailcli.delete_trail(
                Name=trail_name
            )
            print("Trail deleted %s" % trail_name)
        except ClientError as e:
            print("Error in deleting trail %s" % e.response['Error'])
            raise
        except Exception as e:
            print("Error in deleting trail %s" % e)
            raise

    def _transform_bool_values(self, k, v):
        if k in self.boolean_params:
            return True if v and v == "true" else False
        else:
            return v

    def extract_params(self, event):
        props = event.get("ResourceProperties")
        parameters = ["S3BucketName", "S3KeyPrefix", "IncludeGlobalServiceEvents", "IsMultiRegionTrail",
                      "EnableLogFileValidation", "IsOrganizationTrail"]
        params = {k: self._transform_bool_values(k, v) for k, v in props.items() if k in parameters}
        params['Name'] = props.get("TrailName")
        return {
            "props": props,
            "trail_name": props.get("TrailName"),
            "params": params
        }


class TagAWSResources(AWSResource):

    def __init__(self, props, *args, **kwargs):
        print('Tagging aws resource %s' % props.get("AWSResource"))

    def _tag_aws_resources(self, region_value, aws_resource, tags, account_id, delete_flag, filter_regex):
        # Get the class instance based on AWS Resource
        tag_resource = AWSResourcesProvider.get_provider(aws_resource, region_value, account_id)

        # Fetch and Filter the Resources.
        resources = tag_resource.fetch_resources()
        filtered_resources = tag_resource.filter_resources(filter_regex, resources)

        if filtered_resources:
            # Get the ARNs for all resources
            arns = tag_resource.get_arn_list(filtered_resources)

            # Tag or un-tag the resources.
            if delete_flag:
                tag_resource.delete_tags(arns, tags)
            else:
                tag_resource.add_tags(arns, tags)

    def create(self, region_value, aws_resource, tags, account_id, filter_regex, *args, **kwargs):
        print("TAG AWS RESOURCES - Starting the AWS resources Tag addition with Tags %s." % tags)
        regions = [region_value]
        for region in regions:
            self._tag_aws_resources(region, aws_resource, tags, account_id, False, filter_regex)
        print("TAG AWS RESOURCES - Completed the AWS resources Tag addition.")

        return {"TAG_CREATION": "Successful"}, "Tag"

    def update(self, region_value, aws_resource, tags, account_id, filter_regex, *args, **kwargs):
        self.create(region_value, aws_resource, tags, account_id, filter_regex, *args, **kwargs)
        print("updated tags for aws resource %s " % aws_resource)
        return {"TAG_UPDATE": "Successful"}, "Tag"

    def delete(self, region_value, aws_resource, tags, account_id, filter_regex, remove_on_delete_stack, *args,
               **kwargs):
        tags_list = []
        if tags:
            tags_list = list(tags.keys())
        print("TAG AWS RESOURCES - Starting the AWS resources Tag deletion with Tags %s." % tags_list)
        if remove_on_delete_stack:
            regions = [region_value]
            for region in regions:
                self._tag_aws_resources(region, aws_resource, tags, account_id, True, filter_regex)
            print("TAG AWS RESOURCES - Completed the AWS resources Tag deletion.")
        else:
            print("TAG AWS RESOURCES - Skipping AWS resources tags deletion.")

    def extract_params(self, event):
        props = event.get("ResourceProperties")
        tags = {}
        if "Tags" in props:
            tags = props.get("Tags")
        return {
            "region_value": props.get("Region"),
            "aws_resource": props.get("AWSResource"),
            "tags": tags,
            "account_id": props.get("AccountID"),
            "filter_regex": props.get("Filter"),
            "remove_on_delete_stack": props.get("RemoveOnDeleteStack")
        }


class EnableS3LogsResources(AWSResource):

    def __init__(self, props, *args, **kwargs):
        print('Enabling S3 for ALB aws resource %s' % props.get("AWSResource"))

    def _s3_logs_alb_resources(self, region_value, aws_resource, bucket_name, bucket_prefix,
                               delete_flag, filter_regex, region_account_id, account_id):

        # Get the class instance based on AWS Resource
        tag_resource = AWSResourcesProvider.get_provider(aws_resource, region_value, account_id)

        # Fetch and Filter the Resources.
        resources = tag_resource.fetch_resources()
        filtered_resources = tag_resource.filter_resources(filter_regex, resources)

        if filtered_resources:
            # Get the ARNs for all resources
            arns = tag_resource.get_arn_list(filtered_resources)

            # Enable and disable AWS ALB S3 the resources.
            if delete_flag:
                tag_resource.disable_s3_logs(arns, bucket_name)
            else:
                tag_resource.enable_s3_logs(arns, bucket_name, bucket_prefix, region_account_id)

    def create(self, region_value, aws_resource, bucket_name, bucket_prefix, filter_regex, region_account_id,
               account_id, *args, **kwargs):
        print("ENABLE S3 LOGS - Starting the AWS resources S3 addition to bucket %s." % bucket_name)
        self._s3_logs_alb_resources(region_value, aws_resource, bucket_name, bucket_prefix,
                                    False, filter_regex, region_account_id, account_id)
        print("ENABLE S3 LOGS - Completed the AWS resources S3 addition to bucket.")

        return {"S3_ENABLE": "Successful"}, "S3"

    def update(self, region_value, aws_resource, bucket_name, bucket_prefix, filter_regex, region_account_id,
               account_id, *args, **kwargs):
        self.create(region_value, aws_resource, bucket_name, bucket_prefix, filter_regex, region_account_id,
                    account_id, *args, **kwargs)
        print("updated S3 bucket to %s " % bucket_name)
        return {"S3_ENABLE": "Successful"}, "S3"

    def delete(self, region_value, aws_resource, bucket_name, bucket_prefix, filter_regex, remove_on_delete_stack,
               account_id, *args, **kwargs):
        if remove_on_delete_stack:
            self._s3_logs_alb_resources(region_value, aws_resource, bucket_name, bucket_prefix, True,
                                        filter_regex, "", account_id)
            print("ENABLE S3 LOGS - Completed the AWS resources S3 deletion to bucket.")
        else:
            print("ENABLE S3 LOGS - Skipping the AWS resources S3 deletion to bucket.")

    def extract_params(self, event):
        props = event.get("ResourceProperties")
        return {
            "region_value": os.environ.get("AWS_REGION"),
            "aws_resource": props.get("AWSResource"),
            "bucket_name": props.get("BucketName"),
            "bucket_prefix": props.get("BucketPrefix"),
            "filter_regex": props.get("Filter"),
            "region_account_id": props.get("RegionAccountId"),
            "remove_on_delete_stack": props.get("RemoveOnDeleteStack"),
            "account_id": props.get("AccountID")
        }


class ConfigDeliveryChannel(AWSResource):

    def __init__(self, *args, **kwargs):
        self.config_client = boto3.client('config', region_name=os.environ.get("AWS_REGION"))

    def create(self, delivery_frequency, bucket_name, bucket_prefix, sns_topic_arn, *args, **kwargs):
        print("DELIVERY CHANNEL - Starting the AWS config Delivery channel create with bucket %s." % bucket_name)

        name = "default"
        if not bucket_name:
            channels = self.config_client.describe_delivery_channels()
            if "DeliveryChannels" in channels:
                for channel in channels["DeliveryChannels"]:
                    bucket_name = channel["s3BucketName"]
                    if not bucket_prefix:
                        bucket_prefix = channel["s3KeyPrefix"] if "s3KeyPrefix" in channel else None
                    name = channel["name"]
                    break

        delivery_channel = {"name": name, "s3BucketName": bucket_name}

        if bucket_prefix:
            delivery_channel["s3KeyPrefix"] = bucket_prefix
        if sns_topic_arn:
            delivery_channel["snsTopicARN"] = sns_topic_arn
        if delivery_frequency:
            delivery_channel["configSnapshotDeliveryProperties"] = {'deliveryFrequency': delivery_frequency}

        self.config_client.put_delivery_channel(DeliveryChannel=delivery_channel)

        print("DELIVERY CHANNEL - Completed the AWS config Delivery channel create.")

        return {"DELIVERY_CHANNEL": "Successful"}, name

    def update(self, delivery_frequency, bucket_name, bucket_prefix, sns_topic_arn, *args, **kwargs):
        print("updated delivery channel to %s " % bucket_name)
        return self.create(delivery_frequency, bucket_name, bucket_prefix, sns_topic_arn, *args, **kwargs)

    def delete(self, delivery_channel_name, bucket_name, delivery_frequency, remove_on_delete_stack, *args, **kwargs):
        if remove_on_delete_stack:
            if not bucket_name:
                self.create(delivery_frequency, None, None, None)
            else:
                self.config_client.delete_delivery_channel(DeliveryChannelName=delivery_channel_name)
            print("DELIVERY CHANNEL - Completed the AWS Config delivery channel delete.")
        else:
            print("DELIVERY CHANNEL - Skipping the AWS Config delivery channel delete.")

    def extract_params(self, event):
        props = event.get("ResourceProperties")
        delivery_channel_name = None
        if event.get('PhysicalResourceId'):
            _, delivery_channel_name = event['PhysicalResourceId'].split("/")

        return {
            "delivery_frequency": props.get("DeliveryFrequency"),
            "bucket_name": props.get("S3BucketName"),
            "bucket_prefix": props.get("S3KeyPrefix"),
            "sns_topic_arn": props.get("SnsTopicARN"),
            "remove_on_delete_stack": props.get("RemoveOnDeleteStack"),
            "delivery_channel_name": delivery_channel_name
        }


def resource_tagging(event, context):
    print("AWS RESOURCE TAGGING :- Starting resource tagging")

    # Get Account Id and Alias from env.
    account_alias = os.environ.get("AccountAlias")
    account_id = os.environ.get("AccountID")
    filter_regex = os.environ.get("Filter")

    tags = {'account': account_alias}

    if "detail" in event:
        event_detail = event.get("detail")
        event_name = event_detail.get("eventName")
        region_value = event_detail.get("awsRegion")

        # Get the class instance based on Cloudtrail Event Name
        tag_resource = AWSResourcesProvider.get_provider(event_name, region_value, account_id)
        event_detail = tag_resource.filter_resources(filter_regex, event_detail)

        if event_detail:
            # Get the arns from the event.
            resources = tag_resource.get_arn_list_cloud_trail_event(event_detail)

            # Process the existing tags to add some more tags if necessary
            tags = tag_resource.process_tags(tags)

            # Tag the resources
            tag_resource.tag_resources_cloud_trail_event(resources, tags)

    print("AWS RESOURCE TAGGING :- Completed resource tagging")


def enable_s3_logs(event, context):
    print("AWS S3 ENABLE ALB :- Starting s3 logs enable")
    # Get Account Id and Alias from env.
    bucket_name = os.environ.get("BucketName")
    bucket_prefix = os.environ.get("BucketPrefix")
    account_id = os.environ.get("AccountID")
    filter_regex = os.environ.get("Filter")
    region_account_id = os.environ.get("RegionAccountId")

    if "detail" in event:
        event_detail = event.get("detail")
        event_name = event_detail.get("eventName")
        region_value = event_detail.get("awsRegion")

        # Get the class instance based on Cloudtrail Event Name
        alb_resource = AWSResourcesProvider.get_provider(event_name, region_value, account_id)
        event_detail = alb_resource.filter_resources(filter_regex, event_detail)

        if event_detail:
            # Get the arns from the event.
            resources = alb_resource.get_arn_list_cloud_trail_event(event_detail)

            # Enable S3 logging
            alb_resource.enable_s3_logs(resources, bucket_name, bucket_prefix, region_account_id)

    print("AWS S3 ENABLE ALB :- Completed s3 logs enable")


@six.add_metaclass(AutoRegisterResource)
class AWSResourcesAbstract(object):
    event_resource_map = {
        "RunInstances": "ec2",
        "CreateStage": "apigateway",
        "CreateRestApi": "apigateway",
        "CreateDeployment": "apigateway",
        "CreateTable": "dynamodb",
        "CreateFunction20150331": "lambda",
        "CreateDBCluster": "rds",
        "CreateDBInstance": "rds",
        "CreateLoadBalancer": "elbv2",
        "CreateBucket": "s3"
    }

    def __init__(self, aws_resource, region_value, account_id):
        self.tagging_client = boto3.client('resourcegroupstaggingapi', region_name=region_value)
        self.client = boto3.client(self.event_resource_map[aws_resource] if aws_resource in self.event_resource_map
                                   else aws_resource, region_name=region_value)
        self.region_value = region_value
        self.account_id = account_id

    @abstractmethod
    def fetch_resources(self):
        raise NotImplementedError()

    def filter_resources(self, filter_regex, resources):
        if filter_regex:
            pattern = re.compile(filter_regex)
            if isinstance(resources, list):
                filtered_resources = []
                for resource in resources:
                    matcher = pattern.search(str(resource))
                    if matcher:
                        filtered_resources.append(resource)

                return filtered_resources
            else:
                matcher = pattern.search(str(resources))
                if matcher:
                    return resources
                else:
                    return None
        return resources

    @abstractmethod
    def get_arn_list(self, *args):
        raise NotImplementedError()

    @abstractmethod
    def process_tags(self, *args):
        raise NotImplementedError()

    @abstractmethod
    def get_arn_list_cloud_trail_event(self, *args):
        raise NotImplementedError()

    @abstractmethod
    def tag_resources_cloud_trail_event(self, *args):
        raise NotImplementedError()

    def add_tags(self, arns, tags):
        if arns:
            chunk_records = self._batch_size_chunk(arns, 20)
            for record in chunk_records:
                self.tagging_client.tag_resources(ResourceARNList=record, Tags=tags)

    def delete_tags(self, arns, tags):
        if arns:
            chunk_records = self._batch_size_chunk(arns, 20)
            for record in chunk_records:
                self.tagging_client.untag_resources(ResourceARNList=record, TagKeys=list(tags.keys()))

    def _batch_size_chunk(self, iterable, size=1):
        length = len(iterable)
        for idx in range(0, length, size):
            data = iterable[idx:min(idx + size, length)]
            yield data


class EC2Resources(AWSResourcesAbstract):

    def fetch_resources(self):
        instances = []
        next_token = None
        while next_token != 'END':
            if next_token:
                response = self.client.describe_instances(MaxResults=1000, NextToken=next_token)
            else:
                response = self.client.describe_instances(MaxResults=1000)

            for reservation in response['Reservations']:
                if "Instances" in reservation:
                    instances.extend(reservation['Instances'])

            next_token = response["NextToken"] if "NextToken" in response else None

            if not next_token:
                next_token = 'END'

        return instances

    def get_arn_list(self, resources):
        arns = []
        if resources:
            for resource in resources:
                arns.append(
                    "arn:aws:ec2:" + self.region_value + ":" + self.account_id + ":instance/" + resource['InstanceId'])

        return arns

    def process_tags(self, tags):
        tags["namespace"] = "hostmetrics"

        tags_key_value = []
        for k, v in tags.items():
            tags_key_value.append({'Key': k, 'Value': v})

        return tags_key_value

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = []
        response_elements = event_detail.get("responseElements")
        if response_elements and "instancesSet" in response_elements and "items" in response_elements.get(
                "instancesSet"):
            for item in response_elements.get("instancesSet").get("items"):
                if "instanceId" in item:
                    arns.append(item.get("instanceId"))

        return arns

    @retry(retry_on_exception=lambda exc: isinstance(exc, ClientError), stop_max_attempt_number=10,
           wait_exponential_multiplier=2000, wait_exponential_max=10000)
    def tag_resources_cloud_trail_event(self, arns, tags):
        self.client.create_tags(Resources=arns, Tags=tags)


class ApiGatewayResources(AWSResourcesAbstract):

    def fetch_resources(self):
        api_gateways = []
        next_token = None
        while next_token != 'END':
            if next_token:
                response = self.client.get_rest_apis(limit=500, position=next_token)
            else:
                response = self.client.get_rest_apis(limit=500)

            if "items" in response:
                api_gateways.extend(response["items"])
                for api in response["items"]:
                    id = api["id"]

                    stages = self.client.get_stages(restApiId=id)
                    for stage in stages["item"]:
                        stage["restApiId"] = id
                        api_gateways.append(stage)

            next_token = response["position"] if "position" in response else None

            if not next_token:
                next_token = 'END'

        return api_gateways

    def get_arn_list(self, resources):
        arns = []
        if resources:
            for resource in resources:
                if "stageName" in resource:
                    arns.append("arn:aws:apigateway:" + self.region_value + "::/restapis/" + resource["restApiId"]
                                + "/stages/" + resource["stageName"])
                else:
                    arns.append("arn:aws:apigateway:" + self.region_value + "::/restapis/" + resource["id"])

        return arns

    def process_tags(self, tags):
        return tags

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = []
        event_name = event_detail.get("eventName")

        if "responseElements" in event_detail:
            response_elements = event_detail.get("responseElements")
            if response_elements and "self" in response_elements:
                details = response_elements.get("self")
                if event_name == "CreateStage":
                    arns.append("arn:aws:apigateway:" + self.region_value + "::/restapis/"
                                + details.get("restApiId") + "/stages/"
                                + details.get("stageName"))
                elif event_name == "CreateRestApi":
                    arns.append("arn:aws:apigateway:" + self.region_value + "::/restapis/"
                                + details.get("restApiId"))

        if "requestParameters" in event_detail:
            request_parameters = event_detail.get("requestParameters")
            if request_parameters and "restApiId" in request_parameters \
                    and "createDeploymentInput" in request_parameters:
                details = request_parameters.get("createDeploymentInput")
                if event_name == "CreateDeployment":
                    arns.append("arn:aws:apigateway:" + self.region_value + "::/restapis/"
                                + request_parameters.get("restApiId") + "/stages/"
                                + details.get("stageName"))
        return arns

    @retry(retry_on_exception=lambda exc: isinstance(exc, ClientError), stop_max_attempt_number=10,
           wait_exponential_multiplier=2000, wait_exponential_max=10000)
    def tag_resources_cloud_trail_event(self, arns, tags):
        for arn in arns:
            self.client.tag_resource(resourceArn=arn, tags=tags)


class DynamoDbResources(AWSResourcesAbstract):

    def fetch_resources(self):
        tables = []
        next_token = None
        while next_token != 'END':
            if next_token:
                response = self.client.list_tables(Limit=100, ExclusiveStartTableName=next_token)
            else:
                response = self.client.list_tables(Limit=100)

            if "TableNames" in response:
                tables.extend(response["TableNames"])

            next_token = response["LastEvaluatedTableName"] if "LastEvaluatedTableName" in response else None

            if not next_token:
                next_token = 'END'

        return tables

    def get_arn_list(self, resources):
        arns = []
        if resources:
            for resource in resources:
                arns.append("arn:aws:dynamodb:" + self.region_value + ":" + self.account_id + ":table/" + resource)

        return arns

    def process_tags(self, tags):
        tags_key_value = []
        for k, v in tags.items():
            tags_key_value.append({'Key': k, 'Value': v})
        return tags_key_value

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = []

        if "resources" in event_detail:
            for item in event_detail.get("resources"):
                if "ARN" in item:
                    arns.append(item.get("ARN"))
        return arns

    @retry(retry_on_exception=lambda exc: isinstance(exc, ClientError), stop_max_attempt_number=10,
           wait_exponential_multiplier=2000, wait_exponential_max=10000)
    def tag_resources_cloud_trail_event(self, arns, tags):
        for arn in arns:
            self.client.tag_resource(ResourceArn=arn, Tags=tags)


class LambdaResources(AWSResourcesAbstract):

    def fetch_resources(self):
        lambdas = []
        next_token = None
        while next_token != 'END':
            if next_token:
                response = self.client.list_functions(MaxItems=1000, Marker=next_token)
            else:
                response = self.client.list_functions(MaxItems=1000)

            if "Functions" in response:
                lambdas.extend(response["Functions"])

            next_token = response["NextMarker"] if "NextMarker" in response else None

            if not next_token:
                next_token = 'END'

        return lambdas

    def get_arn_list(self, resources):
        arns = []
        if resources:
            for resource in resources:
                arns.append(resource["FunctionArn"])

        return arns

    def process_tags(self, tags):
        return tags

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = []

        if "responseElements" in event_detail:
            response_elements = event_detail.get("responseElements")
            if response_elements and "functionArn" in response_elements:
                arns.append(response_elements.get("functionArn"))
        return arns

    @retry(retry_on_exception=lambda exc: isinstance(exc, ClientError), stop_max_attempt_number=10,
           wait_exponential_multiplier=2000, wait_exponential_max=10000)
    def tag_resources_cloud_trail_event(self, arns, tags):
        for arn in arns:
            self.client.tag_resource(Resource=arn, Tags=tags)


class RDSResources(AWSResourcesAbstract):

    def fetch_resources(self):
        resources = []
        next_token = None
        while next_token != 'END':
            if next_token:
                response = self.client.describe_db_clusters(MaxRecords=100, Marker=next_token)
            else:
                response = self.client.describe_db_clusters(MaxRecords=100)

            if "DBClusters" in response:
                resources.extend(response["DBClusters"])
                for function_name in response["DBClusters"]:
                    cluster_name = function_name['DBClusterIdentifier']
                    next_token = None
                    filters = [{'Name': 'db-cluster-id', 'Values': [cluster_name]}]
                    while next_token != 'END':
                        if next_token:
                            response_instances = self.client.describe_db_instances(MaxRecords=100, Marker=next_token,
                                                                                   Filters=filters)
                        else:
                            response_instances = self.client.describe_db_instances(MaxRecords=100, Filters=filters)

                        if "DBInstances" in response_instances:
                            resources.extend(response_instances["DBInstances"])

                        next_token = response_instances["Marker"] if "Marker" in response_instances else None

                        if not next_token:
                            next_token = 'END'

            next_token = response["Marker"] if "Marker" in response else None

            if not next_token:
                next_token = 'END'

        return resources

    def get_arn_list(self, resources):
        arns = {}
        if resources:
            for resource in resources:
                tags_key_value = []
                if "DBClusterIdentifier" in resource:
                    tags_key_value.append({'Key': "cluster", 'Value': resource['DBClusterIdentifier']})

                function_arn = None
                if "DBInstanceArn" in resource:
                    function_arn = resource["DBInstanceArn"]
                if "DBClusterArn" in resource:
                    function_arn = resource["DBClusterArn"]

                if function_arn in arns:
                    arns[function_arn].extend(tags_key_value)
                else:
                    arns[function_arn] = tags_key_value
        return arns

    def add_tags(self, arns, tags):
        if arns:
            for arn, tags_arn in arns.items():
                tags_key_value = self.process_tags(tags)
                tags_key_value.extend(tags_arn)
                self.client.add_tags_to_resource(ResourceName=arn, Tags=tags_key_value)

    def delete_tags(self, arns, tags):
        if arns:
            for arn, tags_arn in arns.items():
                tags_key_value = self.process_tags(tags)
                tags_key_value.extend(tags_arn)
                tags_keys = [sub['Key'] for sub in tags_key_value]
                self.client.remove_tags_from_resource(ResourceName=arn, TagKeys=tags_keys)

    def process_tags(self, tags):
        tags_key_value = []
        for k, v in tags.items():
            tags_key_value.append({'Key': k, 'Value': v})
        return tags_key_value

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = {}
        event_name = event_detail.get("eventName")
        tags_key_value = []

        if "responseElements" in event_detail:
            response_elements = event_detail.get("responseElements")
            if response_elements:
                if "dBClusterIdentifier" in response_elements:
                    tags_key_value.append({'Key': "cluster", 'Value': response_elements.get("dBClusterIdentifier")})

                if "dBClusterArn" in response_elements and event_name == "CreateDBCluster":
                    arns[response_elements.get("dBClusterArn")] = tags_key_value
                if "dBInstanceArn" in response_elements and event_name == "CreateDBInstance":
                    arns[response_elements.get("dBInstanceArn")] = tags_key_value
        return arns

    @retry(retry_on_exception=lambda exc: isinstance(exc, ClientError), stop_max_attempt_number=10,
           wait_exponential_multiplier=2000, wait_exponential_max=10000)
    def tag_resources_cloud_trail_event(self, arns, tags):
        for arn, tags_arn in arns.items():
            tags.extend(tags_arn)
            self.client.add_tags_to_resource(ResourceName=arn, Tags=tags)


class AlbResources(AWSResourcesAbstract):

    def fetch_resources(self):
        resources = []
        next_token = None
        while next_token != 'END':
            if next_token:
                response = self.client.describe_load_balancers(PageSize=400, Marker=next_token)
            else:
                response = self.client.describe_load_balancers(PageSize=400)

            if "LoadBalancers" in response:
                resources.extend(response['LoadBalancers'])

            next_token = response["NextMarker"] if "NextMarker" in response else None

            if not next_token:
                next_token = 'END'

        return resources

    def get_arn_list(self, resources):
        arns = []
        if resources:
            for resource in resources:
                arns.append(resource['LoadBalancerArn'])
        return arns

    def process_tags(self, tags):
        tags_key_value = []
        for k, v in tags.items():
            tags_key_value.append({'Key': k, 'Value': v})

        return tags_key_value

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = []
        response_elements = event_detail.get("responseElements")
        if response_elements and "loadBalancers" in response_elements:
            for item in response_elements.get("loadBalancers"):
                if "loadBalancerArn" in item:
                    arns.append(item.get("loadBalancerArn"))
        return arns

    @retry(retry_on_exception=lambda exc: isinstance(exc, ClientError), stop_max_attempt_number=10,
           wait_exponential_multiplier=2000, wait_exponential_max=10000)
    def tag_resources_cloud_trail_event(self, arns, tags):
        self.client.add_tags(ResourceArns=arns, Tags=tags)

    def enable_s3_logs(self, arns, s3_bucket, s3_prefix, elb_region_account_id):
        attributes = [{'Key': 'access_logs.s3.enabled', 'Value': 'true'},
                      {'Key': 'access_logs.s3.bucket', 'Value': s3_bucket},
                      {'Key': 'access_logs.s3.prefix', 'Value': s3_prefix}]

        for arn in arns:
            response = self.client.describe_load_balancer_attributes(LoadBalancerArn=arn)
            if "Attributes" in response:
                for attribute in response["Attributes"]:
                    if attribute["Key"] == "access_logs.s3.enabled" and attribute["Value"] == "false":
                        try:
                            self.client.modify_load_balancer_attributes(LoadBalancerArn=arn, Attributes=attributes)
                        except ClientError as e:
                            if "Error" in e.response and "Message" in e.response["Error"] \
                                    and "Access Denied for bucket" in e.response['Error']['Message']:
                                self.add_bucket_policy(s3_bucket, elb_region_account_id)
                                self.enable_s3_logs(arns, s3_bucket, s3_prefix, elb_region_account_id)
                            else:
                                raise e

    def add_bucket_policy(self, bucket_name, elb_region_account_id):
        print("Adding policy to the bucket " + bucket_name)
        s3 = boto3.client('s3')
        try:
            response = s3.get_bucket_policy(Bucket=bucket_name)
            existing_policy = json.loads(response["Policy"])
        except ClientError as e:
            if "Error" in e.response and "Code" in e.response["Error"] \
                    and e.response['Error']['Code'] == "NoSuchBucketPolicy":
                existing_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                    ]
                }
            else:
                raise e

        bucket_policy = {
            'Sid': 'AwsAlbLogs',
            'Effect': 'Allow',
            'Principal': {
                "AWS": "arn:aws:iam::" + elb_region_account_id + ":root"
            },
            'Action': ['s3:PutObject'],
            'Resource': f'arn:aws:s3:::{bucket_name}/*'
        }
        existing_policy["Statement"].append(bucket_policy)

        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(existing_policy))

    def disable_s3_logs(self, arns, s3_bucket):
        attributes = [{'Key': 'access_logs.s3.enabled', 'Value': 'false'}]

        for arn in arns:
            response = self.client.describe_load_balancer_attributes(LoadBalancerArn=arn)
            if "Attributes" in response:
                for attribute in response["Attributes"]:
                    if attribute["Key"] == "access_logs.s3.bucket" and attribute["Value"] == s3_bucket:
                        self.client.modify_load_balancer_attributes(LoadBalancerArn=arn, Attributes=attributes)


class S3Resource(AWSResourcesAbstract):

    def fetch_resources(self):
        resources = []
        response = self.client.list_buckets()

        if "Buckets" in response:
            resources.extend(response['Buckets'])

        return resources

    def get_arn_list(self, resources):
        arns = []
        if resources:
            for bucket_detail in resources:
                bucket_name = bucket_detail["Name"]
                response = self.client.get_bucket_location(Bucket=bucket_name)
                if "LocationConstraint" in response:
                    location = response["LocationConstraint"]
                    if (location is None and self.region_value == "us-east-1") \
                            or (location and self.region_value in response["LocationConstraint"]):
                        arns.append(bucket_name)
        return arns

    def process_tags(self, tags):
        return tags

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = []
        request_elements = event_detail.get("requestParameters")
        if request_elements and "bucketName" in request_elements:
            arns.append(request_elements.get("bucketName"))
        return arns

    def tag_resources_cloud_trail_event(self, *args):
        pass

    def enable_s3_logs(self, arns, s3_bucket, s3_prefix, region_account_id):

        bucket_logging = {'LoggingEnabled': {'TargetBucket': s3_bucket, 'TargetPrefix': s3_prefix}}

        if arns:
            for bucket_name in arns:
                if bucket_name != s3_bucket:
                    response = self.client.get_bucket_logging(Bucket=bucket_name)
                    if not ("LoggingEnabled" in response and "TargetBucket" in response["LoggingEnabled"]):
                        try:
                            self.client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus=bucket_logging)
                        except ClientError as e:
                            if "Error" in e.response and "Message" in e.response["Error"] \
                                    and "InvalidTargetBucketForLogging" in e.response['Error']['Code']:
                                self.client.put_bucket_acl(
                                    Bucket=s3_bucket,
                                    GrantWrite='uri=http://acs.amazonaws.com/groups/s3/LogDelivery',
                                    GrantReadACP='uri=http://acs.amazonaws.com/groups/s3/LogDelivery'
                                )
                                time.sleep(20)
                                self.client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus=bucket_logging)
                            else:
                                raise e

    def disable_s3_logs(self, arns, s3_bucket):
        if arns:
            for bucket_name in arns:
                response = self.client.get_bucket_logging(Bucket=bucket_name)
                if "LoggingEnabled" in response and "TargetBucket" in response["LoggingEnabled"] \
                        and response["LoggingEnabled"]["TargetBucket"] == s3_bucket:
                    self.client.put_bucket_logging(Bucket=bucket_name, BucketLoggingStatus={})


class VpcResource(AWSResourcesAbstract):

    def __init__(self, aws_resource, region_value, account_id):
        super().__init__("ec2", region_value, account_id)
        self.aws_resource = aws_resource

    def fetch_resources(self):
        resources = []
        next_token = None
        while next_token != 'END':
            if next_token:
                response, key = self.client.describe_vpcs(MaxResults=1000, NextToken=next_token)
            else:
                response = self.client.describe_vpcs(MaxResults=1000)

            if "Vpcs" in response:
                resources.extend(response["Vpcs"])

            next_token = response["NextToken"] if "NextToken" in response else None

            if not next_token:
                next_token = 'END'
        return resources

    def get_arn_list(self, resources):
        arns = []
        if resources:
            for resource in resources:
                if "VpcId" in resource:
                    arns.append(resource["VpcId"])
        return arns

    def process_tags(self, tags):
        return tags

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = []
        response_elements = event_detail.get("responseElements")
        if response_elements:
            if "vpc" in response_elements and "vpcId" in response_elements["vpc"]:
                arns.append(response_elements["vpc"]["vpcId"])
        return arns

    def tag_resources_cloud_trail_event(self, *args):
        pass

    def enable_s3_logs(self, arns, s3_bucket, s3_prefix, region_account_id):
        if arns:
            chunk_records = self._batch_size_chunk(arns, 1000)
            for record in chunk_records:
                response = self.client.create_flow_logs(
                    ResourceIds=record,
                    ResourceType='VPC',
                    TrafficType='ALL',
                    LogDestinationType='s3',
                    LogDestination='arn:aws:s3:::' + s3_bucket + '/' + s3_prefix
                )
                if "*Access Denied for LogDestination*" in str(response):
                    self.add_bucket_policy(s3_bucket, s3_prefix)
                    time.sleep(10)
                    self.client.create_flow_logs(
                        ResourceIds=record,
                        ResourceType='VPC',
                        TrafficType='ALL',
                        LogDestinationType='s3',
                        LogDestination='arn:aws:s3:::' + s3_bucket + '/' + s3_prefix
                    )

    def add_bucket_policy(self, bucket_name, prefix):
        print("Adding policy to the bucket " + bucket_name)
        s3 = boto3.client('s3')
        try:
            response = s3.get_bucket_policy(Bucket=bucket_name)
            existing_policy = json.loads(response["Policy"])
        except ClientError as e:
            if "Error" in e.response and "Code" in e.response["Error"] \
                    and e.response['Error']['Code'] == "NoSuchBucketPolicy":
                existing_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                    ]
                }
            else:
                raise e

        bucket_policy = [{
            "Sid": "AWSLogDeliveryAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "delivery.logs.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::" + bucket_name
        },
            {
                "Sid": "AWSLogDeliveryWrite",
                "Effect": "Allow",
                "Principal": {
                    "Service": "delivery.logs.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::" + bucket_name + "/" + prefix + "/AWSLogs/" + self.account_id + "/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            }]
        existing_policy["Statement"].extend(bucket_policy)

        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(existing_policy))

    def disable_s3_logs(self, arns, s3_bucket):
        if arns:
            chunk_records = self._batch_size_chunk(list(arns), 1000)
            for record in chunk_records:
                response = self.client.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': record}])
                if response and "FlowLogs" in response:
                    flow_ids = []
                    for flow_logs in response["FlowLogs"]:
                        if "LogDestination" in flow_logs and s3_bucket in flow_logs["LogDestination"]:
                            flow_ids.append(flow_logs["FlowLogId"])
                    self.client.delete_flow_logs(FlowLogIds=flow_ids)

class NetworkFireWallResource(AWSResourcesAbstract):
    def __init__(self, aws_resource, region_value, account_id):
        super().__init__('network-firewall', region_value, account_id)
        self.aws_resource = aws_resource
    def fetch_resources(self):
        resources = []
        resources_detail = []
        next_token = None
        while next_token != 'END':
            if next_token:
                response = self.client.list_firewalls(MaxResults=50, NextToken=next_token)
            else:
                response = self.client.list_firewalls(MaxResults=50)

            if "Firewalls" in response:
                resources.extend(response["Firewalls"])

            next_token = response["NextToken"] if "NextToken" in response else None

            if not next_token:
                next_token = 'END'
        for fw in resources:
            response = self.client.describe_firewall(FirewallName=fw["FirewallName"],FirewallArn=fw["FirewallArn"])
            if "Firewall" in response:
                resources_detail.append(response)
        return resources_detail
    def get_arn_list(self, resources):
        arns = []
        if resources:
            for resource in resources:
                if "Firewall" in resource:
                    arns.append({'FirewallName':resource['Firewall']['FirewallName'],'FirewallArn':resource['Firewall']['FirewallArn']})
        return arns

    def process_tags(self, tags):
        return tags

    def get_arn_list_cloud_trail_event(self, event_detail):
        arns = []
        response_elements = event_detail.get("responseElements")
        if response_elements:
            if "firewall" in response_elements:
                arns.append({'FirewallName': response_elements['firewall']['firewallName'],'FirewallArn':response_elements['firewall']['firewallArn']})
        return arns

    def tag_resources_cloud_trail_event(self, *args):
        pass

    def enable_s3_logs(self, arns, s3_bucket, s3_prefix, region_account_id):
        if arns:
            for record in arns:
                logging_config_flow = {
                    'LogDestinationConfigs':[
                        {
                            'LogType': 'FLOW',
                            'LogDestinationType': 'S3',
                            'LogDestination': {
                                'bucketName': s3_bucket,
                                'prefix' : s3_prefix
                            }
                        },       
                    ]
                }
                logging_config_flow_alert = {
                    'LogDestinationConfigs':[
                        {
                            'LogType': 'FLOW',
                            'LogDestinationType': 'S3',
                            'LogDestination': {
                                'bucketName': s3_bucket,
                                'prefix' : s3_prefix
                            }
                        }, 
                         {
                            'LogType': 'ALERT',
                            'LogDestinationType': 'S3',
                            'LogDestination': {
                                'bucketName': s3_bucket,
                                'prefix' : s3_prefix
                            }
                        },           
                    ]
                }
                try:
                    #config flow  log for network firewall
                    response = self.client.update_logging_configuration(
                        FirewallArn = record['FirewallArn'],
                        FirewallName = record['FirewallName'],
                        LoggingConfiguration = logging_config_flow
                    )
                    #config addition alert log for network firewall
                    response = self.client.update_logging_configuration(
                        FirewallArn = record['FirewallArn'],
                        FirewallName = record['FirewallName'],
                        LoggingConfiguration = logging_config_flow_alert
                    )
                except Exception as e:
                    continue

    def add_bucket_policy(self, bucket_name, prefix):
        print("Adding policy to the bucket " + bucket_name)
        s3 = boto3.client('s3')
        try:
            response = s3.get_bucket_policy(Bucket=bucket_name)
            existing_policy = json.loads(response["Policy"])
        except ClientError as e:
            if "Error" in e.response and "Code" in e.response["Error"] \
                    and e.response['Error']['Code'] == "NoSuchBucketPolicy":
                existing_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                    ]
                }
            else:
                raise e

        bucket_policy = [{
            "Sid": "AWSLogDeliveryAclCheck",
            "Effect": "Allow",
            "Principal": {
                "Service": "delivery.logs.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "arn:aws:s3:::" + bucket_name
        },
            {
                "Sid": "AWSLogDeliveryWrite",
                "Effect": "Allow",
                "Principal": {
                    "Service": "delivery.logs.amazonaws.com"
                },
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::" + bucket_name + "/" + prefix + "/AWSLogs/" + self.account_id + "/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                }
            }]
        existing_policy["Statement"].extend(bucket_policy)

        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(existing_policy))

    def disable_s3_logs(self, arns, s3_bucket,s3_prefix):
        if arns:
            for record in arns:
                logging_config_flow = {
                    'LogDestinationConfigs':[
                        {
                            'LogType': 'FLOW',
                            'LogDestinationType': 'S3',
                            'LogDestination': {
                                'bucketName': s3_bucket,
                                'prefix' : s3_prefix
                            }
                        },          
                    ]
                }
                logging_config_flow_alert = {
                    'LogDestinationConfigs':[]
                }
                #disable alert log for network firewall
                response = self.client.update_logging_configuration(
                    FirewallArn = record['FirewallArn'],
                    FirewallName = record['FirewallName'],
                    LoggingConfiguration = logging_config_flow
                )
                #disable flow log for network firewall
                response = self.client.update_logging_configuration(
                    FirewallArn = record['FirewallArn'],
                    FirewallName = record['FirewallName'],
                    LoggingConfiguration = logging_config_flow_alert
                )



class AWSResourcesProvider(object):
    provider_map = {
        "ec2": EC2Resources,
        "RunInstances": EC2Resources,
        "apigateway": ApiGatewayResources,
        "CreateStage": ApiGatewayResources,
        "CreateRestApi": ApiGatewayResources,
        "CreateDeployment": ApiGatewayResources,
        "dynamodb": DynamoDbResources,
        "CreateTable": DynamoDbResources,
        "lambda": LambdaResources,
        "CreateFunction20150331": LambdaResources,
        "rds": RDSResources,
        "CreateDBCluster": RDSResources,
        "CreateDBInstance": RDSResources,
        "elbv2": AlbResources,
        "CreateLoadBalancer": AlbResources,
        "s3": S3Resource,
        "CreateBucket": S3Resource,
        "vpc": VpcResource,
        "CreateVpc": VpcResource,
        "CreateFirewall": NetworkFireWallResource,
        "firewall" : NetworkFireWallResource
    }

    @classmethod
    def get_provider(cls, provider_name, region_value, account_id, *args, **kwargs):
        if provider_name in cls.provider_map:
            return cls.provider_map[provider_name](provider_name, region_value, account_id)
        else:
            raise Exception("%s provider not found" % provider_name)

