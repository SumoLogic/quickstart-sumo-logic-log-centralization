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
class AWSCloudTrailOrg(AWSResource):
    def __init__(self, props,  *args, **kwargs):
        self.AWS_SERVICE_PRINCIPAL = "cloudtrail.amazonaws.com"
        self.CLOUDFORMATION_PARAMETERS = ["AWS_PARTITION", "CLOUDTRAIL_NAME", "CLOUDWATCH_LOG_GROUP_ARN",
                             "CLOUDWATCH_LOG_GROUP_ROLE_ARN", "ENABLE_DATA_EVENTS_ONLY", "ENABLE_LAMBDA_DATA_EVENTS",
                             "ENABLE_S3_DATA_EVENTS", "KMS_KEY_ID", "S3_BUCKET_NAME", "S3_KEY_PREFIX", "TAG_KEY1",
                             "TAG_VALUE1"]  
        self.CLOUDTRAIL_CLIENT = boto3.client("cloudtrail")
    def get_data_event_config(self,**params) -> dict:
        """
        Creates the CloudTrail event selectors configuration
        param: params: event parameters
        :return: event_selectors
        """

        if params["enable_data_events_only"]:
            event_selectors = {
                "ReadWriteType": "All",
                "IncludeManagementEvents": False,
                "DataResources": [],
            }
        else:
            event_selectors = {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": [],
            }

        if params["enable_s3_data_events"]:
            s3_data_resource = {
                "Type": "AWS::S3::Object",
                "Values": [f"arn:{params['aws_partition']}:s3:::"]
            }
            event_selectors["DataResources"].append(s3_data_resource)
            logger.info("S3 Data Events Added to Event Selectors")

        if params["enable_lambda_data_events"]:
            lambda_data_resource = {
                "Type": "AWS::Lambda::Function",
                "Values": [f"arn:{params['aws_partition']}:lambda"],
            }
            event_selectors["DataResources"].append(lambda_data_resource)
            logger.info("Lambda Data Events Added to Event Selectors")

        return event_selectors
    def enable_aws_service_access(self,service_principal: str):
        """
        Enables the AWS Service Access for the provided service principal
        :param service_principal: AWS Service Principal format: service_name.amazonaws.com
        :return: None
        """
        logger.info("Enable AWS Service Access for: " + str(service_principal))

        try:
            organizations = boto3.client("organizations")
            organizations.enable_aws_service_access(ServicePrincipal=service_principal)
        except ClientError as ce:
            logger.error(f"Client Error: {str(ce)}")
            raise
        except Exception as exc:
            logger.error(f"Exception: {str(exc)}")
            raise
    def get_cloudtrail_parameters(self, is_create: bool, **params) -> dict:
        """
        Dynamically creates a parameter dict for the CloudTrail create_trail and update_trail API calls.
        :param is_create: True = create, False = update
        :param params: CloudTrail parameters
        :return: cloudtrail_params dict
        """
        cloudtrail_params = {
            "Name": params["cloudtrail_name"],
            "S3BucketName": params["s3_bucket_name"],
            "IncludeGlobalServiceEvents": True,
            "IsMultiRegionTrail": True,
            "EnableLogFileValidation": True,
            "KmsKeyId": params["kms_key_id"],
            "IsOrganizationTrail": True,
        }

        if is_create and params.get("tag_key1", "") and params.get("tag_value1", ""):
            cloudtrail_params["TagsList"] = [{"Key": params["tag_key1"], "Value": params["tag_value1"]}]

        if params.get("s3_key_prefix", ""):
            cloudtrail_params["S3KeyPrefix"] = params["s3_key_prefix"]

        if params.get("cloudwatch_log_group_arn", "") and params.get("cloudwatch_log_group_role_arn", ""):
            cloudtrail_params["CloudWatchLogsLogGroupArn"] = params["cloudwatch_log_group_arn"]
            cloudtrail_params["CloudWatchLogsRoleArn"] = params["cloudwatch_log_group_role_arn"]

        return cloudtrail_params
    def check_parameters(self, event: dict):
        """
        Check event for required parameters in the ResourceProperties
        :param event:
        :return:
        """
        try:
            if "StackId" not in event or "ResourceProperties" not in event:
                raise ValueError("Invalid CloudFormation request, missing StackId or ResourceProperties.")

            # Check CloudFormation parameters
            for parameter in self.CLOUDFORMATION_PARAMETERS:
                if parameter not in event.get("ResourceProperties", ""):
                    raise ValueError("Invalid CloudFormation request, missing one or more ResourceProperties.")

            logger.debug(f"Stack ID : {event.get('StackId')}")
            logger.debug(f"Stack Name : {event.get('StackId').split('/')[1]}")
        except Exception as error:
            logger.error(f"Exception checking parameters {error}")
            raise ValueError("Error checking parameters")
    def create(self, params, *args, **kwargs):
        """
        CloudFormation Create Event. Creates a CloudTrail with the provided parameters
        :param event: event data
        :param context: runtime information
        :return: OrganizationTrailResourceId
        """
        logger.info("Create Event")
        try:
            self.enable_aws_service_access(self.AWS_SERVICE_PRINCIPAL)
            cloudtrail_name = params.get("CLOUDTRAIL_NAME")

            self.CLOUDTRAIL_CLIENT.create_trail(
                **self.get_cloudtrail_parameters(True,
                                            cloudtrail_name=cloudtrail_name,
                                            cloudwatch_log_group_arn=params.get("CLOUDWATCH_LOG_GROUP_ARN"),
                                            cloudwatch_log_group_role_arn=params.get("CLOUDWATCH_LOG_GROUP_ROLE_ARN"),
                                            kms_key_id=params.get("KMS_KEY_ID"),
                                            s3_bucket_name=params.get("S3_BUCKET_NAME"),
                                            s3_key_prefix=params.get("S3_KEY_PREFIX"),
                                            tag_key1=params.get("TAG_KEY1"),
                                            tag_value1=params.get("TAG_VALUE1")
                                            ))
            logger.info("Created an Organization CloudTrail")

            event_selectors = self.get_data_event_config(
                aws_partition=params.get("AWS_PARTITION", "aws"),
                enable_s3_data_events=(params.get("ENABLE_S3_DATA_EVENTS", "false")).lower() in "true",
                enable_lambda_data_events=(params.get("ENABLE_LAMBDA_DATA_EVENTS", "false")).lower() in "true",
                enable_data_events_only=(params.get("ENABLE_DATA_EVENTS_ONLY", "false")).lower() in "true"
            )

            if event_selectors and event_selectors["DataResources"]:

                self.CLOUDTRAIL_CLIENT.put_event_selectors(
                    TrailName=cloudtrail_name,
                    EventSelectors=[event_selectors]
                )

                logger.info("Data Events Enabled")

            self.CLOUDTRAIL_CLIENT.start_logging(Name=cloudtrail_name)
        except ClientError as ce:
            logger.error(f"Unexpected error: {str(ce)}")
            raise ValueError(f"CloudTrail API Exception: {str(ce)}")
        except Exception as exc:
            logger.error(f"Unexpected error: {str(exc)}")
            raise ValueError(f"Exception: {str(exc)}")

        return {"OrganizationTrailResourceId": "QSTrail"}, "QSTrailResourceID"
    def update(self, params, *args, **kwargs):
        self.create(self, params, *args, **kwargs)
    def delete(self, params, *args, **kwargs):
        """
        CloudFormation Delete Event. Deletes the provided CloudTrail
        :param event: event data
        :param context: runtime information
        :return: CloudFormation response
        """
        logger.info("Delete Event")
        try:
            self.CLOUDTRAIL_CLIENT.delete_trail(Name=params.get("CLOUDTRAIL_NAME"))
        except ClientError as ce:
            if ce.response["Error"]["Code"] == "TrailNotFoundException":
                logger.error(f"Trail Does Not Exist {str(ce)}")
                raise ValueError(f"TrailNotFoundException: {str(ce)}")
            else:
                logger.error(f"Unexpected error: {str(ce)}")
                raise ValueError(f"CloudTrail API Exception: {str(ce)}")
        except Exception as exc:
            logger.error(f"Unexpected error: {str(exc)}")
            raise ValueError(f"Exception: {str(exc)}")

        logger.info("Deleted the Organizations CloudTrail")

    def extract_params(self, event):
        props = event.get("ResourceProperties")
        return {
            "params": props
        }                                                                                 


class GuardDuty(AWSResource):

    def __init__(self, props,  *args, **kwargs):

        self.CLOUDFORMATION_PARAMETERS = ["AUTO_ENABLE_S3_LOGS", "AWS_PARTITION", "CONFIGURATION_ROLE_NAME",
                                    "DELEGATED_ADMIN_ACCOUNT_ID", "DELETE_DETECTOR_ROLE_NAME", "ENABLED_REGIONS",
                                    "FINDING_PUBLISHING_FREQUENCY"]
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
                            finding_publishing_frequency: str):

        accounts, account_ids = self.get_all_organization_accounts(delegated_account_id)

        # Loop through the regions and enable GuardDuty
        for region in available_regions:
            try:
                regional_guardduty = self.get_service_client("guardduty", region, session)
                detectors = regional_guardduty.list_detectors()

                if detectors["DetectorIds"]:
                    detector_id = detectors["DetectorIds"][0]
                    logger.info(f"DetectorID: {detector_id} Region: {region}")
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
                    params.get("FINDING_PUBLISHING_FREQUENCY", "FIFTEEN_MINUTES")
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

    def delete(self,params, *args, **kwargs):
        pass

    def extract_params(self, event):
        props = event.get("ResourceProperties")
        return {
            "params": props
        }

#Class config exists s3 resource
class S3ExistsResource(AWSResource):
    def __init__(self, props,  *args, **kwargs):
        self.s3cli = boto3.client('s3')

    def create(self, params, *args, **kwargs):
        bucket_name = params['bucketName']
        kms_arn = params['kmsArn']
        sns_topic = params['snsTopic']

        results_encrypt = self.s3cli.put_bucket_encryption(
                    Bucket=bucket_name,
                    ServerSideEncryptionConfiguration={
                        'Rules': [
                            {
                                'ApplyServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'aws:kms',
                                    'KMSMasterKeyID': kms_arn
                                },
                                'BucketKeyEnabled': False
                            },
                        ]
                    }
                )
        results_notify = self.s3cli.put_bucket_notification_configuration(
                    Bucket=bucket_name,
                    NotificationConfiguration={
                        'TopicConfigurations': [
                        {
                            'TopicArn': sns_topic,
                            'Events': ['s3:ObjectCreated:Put'],
                        },
                    ]
                        
                    }
                )


        return {'ARN': bucket_name}, bucket_name
        

    def update(self, params, *args, **kwargs):
        self.create(params, *args, **kwargs)

    def delete(self, params, *args, **kwargs):
        bucket_name = params['bucketName']
        self.s3cli.delete_bucket_encryption(
            Bucket=bucket_name
        )
        self.s3cli.put_bucket_notification_configuration(
                    Bucket=bucket_name,
                    NotificationConfiguration={  
                    }
                )


    def extract_params(self, event):
        props = event.get("ResourceProperties")
        return {
            "params": props
        }

