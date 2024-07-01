import boto3
import json
from botocore.exceptions import NoCredentialsError, ClientError
import boto3.session
import time
from dotenv import load_dotenv
import os
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
import traceback
import re
import helper

def clients(resource, session):
    return session.client(resource, verify=False)

def session(access_key, secret_key, region_name, token=None):
    if token:
        return boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_name, aws_session_token=token)
    else:
        return boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key, region_name=region_name)

def main():
    helper.load_vars_and_disable_warnings([InsecureRequestWarning])
    app_name = "NewApplication"
    deploy = False
    cross_account_role_arn = os.environ['cross_account_role_arn']
    cross_account_role_session = 'TestSessionName'
    
    # bucket used to store the template if deploy is set to false    
    # innovation s3 bucket to store templates
    #s3_bucket_name = "securityhubexport-innovation"

    # sandbox s3 bucket to store templates
    s3_bucket_name = "patchmanagementpoc"

    
    # if a lambda is part of the application resource list then this s3 bucket(in the destination account) will be used to store the lambda code that will then be used for the lambda deployment
    # innovation lambda code bucket
    #s3_bucket = "securityhubexport-innovation"
    # sandbox lambda code bucket
    s3_bucket = 'patchmanagementpoc'

    region = 'us-east-1'
    main_access_key, main_secret_key = os.environ['innovation_id'], os.environ['innovation_secret']
    session_main = session(main_access_key, main_secret_key, region)
    
    # main account clients
    app_registry_client_main = clients('servicecatalog-appregistry', session_main)
    resource_group_stagging_client_main = clients('resourcegroupstaggingapi', session_main)
    sts_client_main = clients('sts', session_main)
    cloudformation_client_main = clients('cloudformation', session_main)
    lambda_client_main = clients('lambda', session_main)
    iam_client_main = clients('iam', session_main)
    s3_client_main = clients('s3', session_main)
    ec2_client_main = clients('ec2', session_main)
    kms_client_main = clients('kms', session_main)
    
    account_1_access_key, account_1_secret_key, account_1_token = helper.assume_role_session_creds(sts_client_main, cross_account_role_arn, cross_account_role_session)
    session_account_1 = session(account_1_access_key, account_1_secret_key, region, account_1_token)
    
    # destination account clients
    destination_sts_client = clients('sts', session_account_1)
    app_registry_client_account_1 = clients('servicecatalog-appregistry', session_account_1)
    cloudformation_client_account_1 = clients('cloudformation', session_account_1)
    resource_group_stagging_client_account_1 = clients('resourcegroupstaggingapi', session_account_1)
    iam_client_account_1 = clients('iam', session_account_1)
    s3_client_account_1 = clients('s3', session_account_1)
    lambda_client_account_1 = clients('lambda', session_account_1)
    
    
    # Check if application exists in the main account   
    if not helper.check_application_exists(app_registry_client_main, app_name):
        print(f"Application {app_name} does not exist in the prod account.")
        return
    
    # Get all resources part of the application
    resources = helper.get_application_resources(app_registry_client_main, resource_group_stagging_client_main, app_name)
    
    # source and destination account id's
    source_account_id = sts_client_main.get_caller_identity()['Account']
    destination_account_id = destination_sts_client.get_caller_identity()['Account']

    # stack names for the iam roles/policies and the resources
    stack_name = f"{app_name}--iam-stack"
    stack_name_resources = f"{app_name}--stack"
    
    # create applications in other account if they do not exist
    # if they do exist then tag existing resources and create new necessary resources
    try:
        if not helper.check_application_exists(app_registry_client_account_1, app_name):
            print(f"Creating application {app_name} in {'account_name'}.")
            app_id = helper.create_application(app_registry_client_account_1, app_name)
            #app_id = False
            application_tag = helper.get_application_tag(app_registry_client_account_1, app_name)
            temp_stack_name = app_name + '--stack'
            stack_exist = stack_exists(cloudformation_client_account_1, temp_stack_name)
            resources_to_tag = []
            for resource_arn in resources:
                updated_arn = resource_arn['ResourceARN'].replace(source_account_id, destination_account_id)
                resources_to_tag.append(updated_arn)
            failed_resources = tag_resources(resource_group_stagging_client_account_1, resources_to_tag, {application_tag[0]: application_tag[1]})
            if stack_exist:
                resources_to_tag = []
                if failed_resources:
                    for resource in failed_resources:
                        updated_arn = resource.replace(destination_account_id, source_account_id)
                        resources_to_tag.append(updated_arn)
                    create_and_deploy_stack(app_name, resources_to_tag, cloudformation_client_account_1,lambda_client_main, lambda_client_account_1, iam_client_main, s3_client_main, ec2_client_main, kms_client_main, iam_client_account_1, s3_client_account_1, source_account_id, destination_account_id, application_tag, stack_name, stack_name_resources, 'account_name', app_registry_client_account_1, app_id, deploy, s3_bucket)
                print(f"Resources from existing stack(s) were added to application {app_name}")
            else:
                create_and_deploy_stack(app_name, resources, cloudformation_client_account_1,lambda_client_main, lambda_client_account_1, iam_client_main, s3_client_main, ec2_client_main, kms_client_main, iam_client_account_1, s3_client_account_1, source_account_id, destination_account_id, application_tag, stack_name, stack_name_resources, 'account_name', app_registry_client_account_1, app_id, deploy, s3_bucket)
        else:
            application_tag = get_application_tag(app_registry_client_account_1, app_name)
            resources_application_2 = get_application_resources(app_registry_client_account_1, resource_group_stagging_client_account_1, app_name)
            
            # compare the resources here. since the application exists check if the resources are all there
            comparing_resources = compare_and_create_resources(resources, resources_application_2, cloudformation_client_main, lambda_client_main, iam_client_main, s3_client_main, ec2_client_main, kms_client_main, iam_client_account_1, s3_client_account_1, cloudformation_client_account_1, lambda_client_account_1, resource_group_stagging_client_account_1, source_account_id, destination_account_id, stack_name, stack_name_resources, application_tag, s3_bucket, deploy, app_name)
                
    except Exception as e:
        print(traceback.format_exc())
        print(str(e))
            
if __name__ == "__main__":
    # STEPS:
    # Pre reqs: 
    #   Assume role in destination account to get access to applications and resources
    #   Create necessary resource clients for both accounts
    # 1. Check if an application from the prod (or any other higher level acocunt) exists in the lower environment
    # 2. If the application doesn't exist in the account then create a cloudformation template for all resources in the application
    #     2.1 Two templates, 1 for the resources and the 2nd for the IAM roles and permissions needed for the resource
    # 3. Store lambda zip file to s3 bucket in destination account in order to replicate lambda
    # 4. Create an application usng service catalog in the account
    # 5. Deploy the stack in the account
    # 5.1 stack can also be saved to an s3 bucket
    
    
    main()
 
    