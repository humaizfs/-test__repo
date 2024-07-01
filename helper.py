def load_vars_and_disable_warnings(warnings_to_disable):
    load_dotenv()
    for warning in warnings_to_disable:
        disable_warnings(warning)

def assume_role_session_creds(sts_client_main, role_arn, role_session_name):
    creds = sts_client_main.assume_role(RoleArn=role_arn, RoleSessionName=role_session_name)['Credentials']
    access_key = creds['AccessKeyId']
    secret_key = creds['SecretAccessKey']
    token = creds['SessionToken']
    
    return access_key, secret_key, token

def stack_exists(cloudformation_client, stack_name, required_status=['CREATE_COMPLETE', 'UPDATE_COMPLETE']):
    try:
        response = cloudformation_client.describe_stacks(StackName=stack_name)
        return response['Stacks'][0]['StackStatus'] in required_status
    except ClientError as e:
        return False
    
def lambda_exists(lambda_client, lambda_name):
    try:
        response = lambda_client.get_function(FunctionName=lambda_name)
        return True
    except Exception as e:
        return False
    
def check_application_exists(app_registry_client, app_name):
    try:
        response = app_registry_client.list_applications()
        for app in response['applications']:
            if app['name'] == app_name:
                return True
        return False
    except Exception as e:
        print(f"Error checking application existence: {e}")
        return False
    
def check_role_exists(iam_client, role_name):
    try:
        response = iam_client.get_role(RoleName=role_name)
        return True
    except iam_client.exceptions.NoSuchEntityException as e:
        return False
    
def check_policy_exists(iam_client, policy_name):
    response = iam_client.list_policies()

    policies = response['Policies']

    for policy in policies:
        policy_name_destination_account = policy['PolicyName']
        if policy_name_destination_account == policy_name:
            return True
        
def tag_resources(tagging_client, resource_arn_list, tags_dict):
    try:
        response = tagging_client.tag_resources(ResourceARNList=resource_arn_list, Tags=tags_dict)
        print("Existing resources were tagged with application tag")
        failed_resources = []
        if 'FailedResourcesMap' in response.keys():
            for resource in response['FailedResourcesMap']:
                failed_resources.append(resource)
        return failed_resources
    except Exception as e:
        print(e)
        return None

def get_application_tag(app_registry_client, app_name):
    try:
        response = app_registry_client.list_applications()
        arn = ''
        for app in response['applications']:
            if app['name'] == app_name:
                app_tag = app_registry_client.get_application(application=app_name)['applicationTag']
                app_tag_key = (list(app_tag.keys())[0])
                app_tag_value = str(app_tag[list(app_tag.keys())[0]])
                return [app_tag_key, app_tag_value]
        return []
    except Exception as e:
        print(f"Error getting application resources: {e}")
        return []

def get_application_resources(app_registry_client, tagging_client, app_name):
    try:
        response = app_registry_client.list_applications()
        arn = ''
        for app in response['applications']:
            if app['name'] == app_name:
                app_id = app['id']
                app_tag = app_registry_client.get_application(application=app_name)['applicationTag']
                app_tag_key = (list(app_tag.keys())[0])
                app_tag_value = str(app_tag[list(app_tag.keys())[0]])
                app_tag_value_list = [app_tag_value]
                #print(app_tag_key, app_tag_value)
                resources = tagging_client.get_resources(TagFilters=[{'Key': list(app_tag.keys())[0], 'Values': app_tag_value_list}])
                resources = (list(resources['ResourceTagMappingList']))
                return resources
        return []
    except Exception as e:
        print(f"Error getting application resources: {e}")
        return []
    
def upload_lambda_code_to_s3(lambda_code_url, s3_client, s3_bucket):
    code_url = lambda_code_url.split('https://')
    split_version_id = code_url[1].split('?versionId=')
    s3_info = split_version_id[0].split('.s3.us-east-1.amazonaws.com/')
    s3_file_name = s3_info[1].split('/')[-1]
    # 
    file_url = lambda_code_url
    s3_key = s3_file_name + '.zip'

    try:
        # Stream the file content from the url
        response = requests.get(file_url, stream=True)
        response.raise_for_status()  # Check if the request was successful
        # Upload the streamed file content to S3
        s3_client.upload_fileobj(response.raw, s3_bucket, s3_key)
        #print(f"File uploaded to {bucket_name}/{s3_key} successfully.")
        return s3_bucket, s3_key
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file from URL: {e}")
    except NoCredentialsError:
        print("Credentials not available")
    except Exception as e:
        print(f"An error occurred: {e}")
        
def write_template_to_s3_bucket(s3_client, bucket, body, key):
    response = s3_client.put_object(Bucket=bucket, Body=body, Key=key + '.json')
    return response

def get_lambda_function_details(lambda_client, s3_bucket, destination_s3_client, id):
    response = lambda_client.get_function(FunctionName=id)
    configuration = response['Configuration']
    code = response['Code']
    
    try:
        s3_bucket, s3_key = upload_lambda_code_to_s3(code['Location'], destination_s3_client, s3_bucket)
    except:
        print('Put Object access denied or Invalid s3 bucket name')
        return
    
    layers = []
    if 'Layers' in configuration:
        for layer in configuration['Layers']:
            layers.append(layer['Arn'])
    
    environment = {}        
    if 'Environment' in configuration:
        environment = configuration['Environment']
    
    tags = []
    if 'Tags' in response.keys():
        for n in response['Tags']:
            temp = {}
            temp['Value'] = response['Tags'][n] 
            temp['Key'] = n
            tags.append(temp)

    for tag in tags:
        if tag['Key'].startswith('aws:'):
            tags.remove(tag)
        
    for tag in tags:
        if tag['Key'].startswith('aws:'):
            tags.remove(tag)

    return {
        'FunctionName': configuration['FunctionName'],
        'Handler': configuration['Handler'],
        
        'Code': {
            'S3Bucket': s3_bucket,
            'S3Key': s3_key,
            #'S3ObjectVersion': version_id
        },
        'MemorySize': configuration['MemorySize'],
        'Role': configuration['Role'],
        'Runtime': configuration['Runtime'],
        'Timeout': configuration['Timeout'],
        'TracingConfig': {
            'Mode': configuration['TracingConfig']['Mode']
        },
        'EphemeralStorage': {
            'Size': configuration['EphemeralStorage']['Size']
        },
        'Tags': tags,
        'Environment': environment,
        'Layers': layers
    }

def get_ec2_instance_details(client, id):
    response = client.describe_instances(InstanceIds=[id])
    instance = response['Reservations'][0]['Instances'][0]
    
    return {
        'InstanceId': instance['InstanceId'],
        'InstanceType': instance['InstanceType'],
        'KeyName': instance['KeyName'],
        'SubnetId': instance['SubnetId'],
        'SecurityGroupIds': [sg['GroupId'] for sg in instance['SecurityGroups']],
        'IamInstanceProfile': instance.get('IamInstanceProfile', {}).get('Arn')
    }

def get_s3_bucket_details(client, bucket):
    response = client.get_bucket_location(Bucket=bucket)
    location = response['LocationConstraint']
    
    return {
        'BucketName': bucket,
        'LocationConstraint': location
    }

def create_managed_policy_template(iam_client, role_name, policy_arn, destination_account_id):
    policy_version = iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
    policy = iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=policy_version)
    managed_policy_name = policy_arn.split('/')[-1]
    path = policy_arn.split('policy/')[-1]
    new_path = ''
    if path == managed_policy_name:
        new_path = '/'
    else:
        new_path = '/' + path.replace(managed_policy_name, '')
        
    document = policy['PolicyVersion']['Document']
    
    return {
        "ManagedPolicyName": managed_policy_name,
        "Path": new_path,
        "PolicyDocument": document
    }

def create_role_template(iam_client, destination_iam_client, role_name, destination_account_id):
    role = iam_client.get_role(RoleName=role_name)['Role']
    assume_role_policy = role['AssumeRolePolicyDocument']
    path = role['Path']

    # Fetch inline policies
    inline_policies = iam_client.list_role_policies(RoleName=role_name)['PolicyNames']
    inline_policies_docs = {}
    for policy_name in inline_policies:
        policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
        inline_policies_docs[policy_name] = policy_doc

    # Fetch managed policies
    managed_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
    managed_policy_arns = [policy['PolicyArn'] for policy in managed_policies]

    # Create CloudFormation template with parameters
    cloudformation_template = {
        "Path": path,
        "AssumeRolePolicyDocument": assume_role_policy,
        "RoleName": role_name,
        "ManagedPolicyArns": managed_policy_arns,
        "Policies": []
    }
    
    # Add inline policies to the template
    for policy_name, policy_doc in inline_policies_docs.items():
        if not check_policy_exists(destination_iam_client, policy_name):
            policy = {
                "PolicyName": policy_name,
                "PolicyDocument": policy_doc
            }
            cloudformation_template["Policies"].append(policy)
        else:
            policy = {
                "PolicyName": policy_name
            }
            cloudformation_template["Policies"].append(policy)

    return cloudformation_template
    
def get_kms_details(client, id):
    key_details = client.describe_key(KeyId=id)
    key_policy = client.get_key_policy(KeyId=key_details['KeyMetadata']['KeyId'])
    #public_key = client.get_public_key(KeyId=key_details['KeyMetadata']['KeyId'])

    properties = {
        'Enabled': key_details['KeyMetadata']['Enabled'],
        'Description': key_details['KeyMetadata']['Description'],
        'KeyPolicy': key_policy['Policy'],
        'KeySpec': key_details['KeyMetadata']['KeySpec'],
    }

    return properties

def create_application(client, app_name):
    try:
        response = client.create_application(
            name=app_name,
            description='Created by automation script'
        )
        return response['application']['id']
    except Exception as e:
        print(f"Error creating application: {e}")
        return None

def delete_application(client, app_name):
    try:
        repsonse = client.delete_application(
            application=app_name,
        )
        return repsonse
    except Exception as e:
        print(f"Error deleting application: {e}")
        return None

def deploy_stack(cloudformation_client, stack_name, template_body):
    if stack_exists(cloudformation_client, stack_name):
        stack_name = increment_name_count(stack_name, cloudformation_client)
        recursive_response = deploy_stack(cloudformation_client, stack_name, template_body)
        return recursive_response
    
    else:
        try:
            cloudformation_client.validate_template(
                TemplateBody=template_body
            )
            
            try:
                response = cloudformation_client.create_stack(
                    StackName=stack_name,
                    TemplateBody=template_body,
                    Capabilities=['CAPABILITY_NAMED_IAM']
                )
                print(f"Stack {stack_name} deployed successfully.")
                return response['StackId']
            except cloudformation_client.exceptions.AlreadyExistsException as e:
                print(e)
                return 'StackExists'
            except Exception as e:
                print(f"Error occurred while creating stack: {e}")
                return None
        
        except Exception as e:
            print(f"Template failed validation, exception : {e}")
            return None

def increment_name_count(name, cf_client):
    count = re.findall(r'\d+', name)
    if count:
        count = count[0]
        updated_count = str(int(count)+1)
        name = name.replace(count,updated_count)
        if not stack_exists(cf_client, name):
            return name
        updated_name = increment_name_count(name, cf_client)
        if not stack_exists(cf_client,updated_name):
            return updated_name
    else:
        name = name.split('--')
        if len(name) == 2:
            updated_name = name[0] + '1--' + name[1]
            if not stack_exists(cf_client,updated_name):
                return updated_name
        elif len(name) == 3:
            updated_name = name[0] + '1--' + name[1] + '--' + name[2]
            if not stack_exists(cf_client,updated_name):
                return updated_name

def deploy_or_update_stack(cf_client, stack_name, cf_template, destination_account_id):
    try:
        cf_client.validate_template(
            TemplateBody=cf_template
        )
        #check if stack already exists
        try:
            cf_client.describe_stacks(StackName=stack_name)
            stack_exists = True
        except cf_client.exceptions.ClientError as e:
            if "does not exist" in str(e):
                stack_exists = False
            else:
                raise
        response = ''
        action = "updated"
        if stack_exists:
            stack_name = increment_name_count(stack_name, cf_client)
            deploy_or_update_stack(cf_client, stack_name, cf_template, destination_account_id)
        
        else:
            #create a new stack
            resopnse = cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=cf_template,
                Capabilities=['CAPABILITY_NAMED_IAM']
            )
            action = "created"
        
            print(f"Stack {stack_name} {action} in the destination account {destination_account_id}.")
        
        return response
    except Exception as e:
        print(traceback.format_exc())
        print(f"Template failed validation, exception: {e}")
        return None
    
def verify_resources_exist(lambda_client, s3_client, kms_client, resource_arns):
    existing_resources = []
    for arn in resource_arns:
        try:
            resource_type = arn.split(':')[2]
            resource_id = arn.split('/')[-1]
            if resource_type == 'lambda':
                lambda_client.get_function(FunctionName=resource_id)
            elif resource_type == 's3':
                s3_client.get_bucket_policy(Bucket=resource_id)
            existing_resources.append(arn)
        except Exception as e:
            #print(f"Resource {arn} does not exist or is not accessible: {e}")
            continue
    return existing_resources
    
def add_tag_to_resource(tagging_api_client, resource_arn, application_tag):
    print(f"Resource '{resource_arn}' was found and tagged in destination account")
    response = tagging_api_client.tag_resources(ResourceARNList=[resource_arn], Tags={application_tag[0]: application_tag[1]})
    return response

# currently only untags resource instad of deleting
def delete_resources(tagging_api_client, resource_arn, application_tag):
    print(f"Resource '{resource_arn}' was removed from application resource list")
    response = tagging_api_client.untag_resources(ResourceARNList=[resource_arn], TagKeys=[application_tag[0]])
    return response


def compare_and_create_resources(resource_arns_account_1, resource_arns_account_2, cf_client_account_1, lambda_client_main, iam_client_main, s3_client_main, ec2_client_main, kms_client_main, iam_client_account_1, s3_client_account_1, cf_client_account_2, lambda_client_account_1, resource_group_stagging_client_account_1, source_account_id, destination_account_id, stack_name_roles, stack_name_resources, application_tag, lambda_code_storage_bucket, deploy, app_name):
    for arn in resource_arns_account_2:
        account_2_resource_type = arn['ResourceARN'].split(':')[2]
        if account_2_resource_type == 's3':
            resource_arns_account_2[arn]['ResourceARN'] = arn['ResourceARN'] + '-' + destination_account_id
    
    account_1_resource_names = {arn['ResourceARN'].split(':')[-1] for arn in resource_arns_account_1}
    account_2_resource_names = {arn['ResourceARN'].split(':')[-1] for arn in resource_arns_account_2}

    missing_resource_names = account_1_resource_names - account_2_resource_names
    
    # resources that should be deleted form application 2
    missing_resources_names_account_1 = account_2_resource_names - account_1_resource_names
    
    missing_resource_arns = [arn['ResourceARN'] for arn in resource_arns_account_1 if arn['ResourceARN'].split(':')[-1] in missing_resource_names]
    updated_missing_resource_arns = []
    
    missing_resource_arns_account_2 = [arn['ResourceARN'] for arn in resource_arns_account_2 if arn['ResourceARN'].split(':')[-1] in missing_resources_names_account_1]

    #replace account id
    for resource in missing_resource_arns:
        updated_missing_resource_arns.append(resource.replace(source_account_id, destination_account_id))   

    resources_to_tag = verify_resources_exist(lambda_client_account_1, s3_client_account_1, kms_client_main, updated_missing_resource_arns)

    resources_to_create = []

    for arn in updated_missing_resource_arns:
        if arn in resources_to_tag:
            add_tag_to_resource(resource_group_stagging_client_account_1, arn, application_tag)
        else:

            resources_to_create.append(arn.replace(destination_account_id, source_account_id))

    resources_to_delete = []
    for arn in missing_resource_arns_account_2:
        resources_to_delete.append(arn)
        delete_resources(resource_group_stagging_client_account_1, arn, application_tag)

    if not resources_to_create:
        print('Application is standardized across both accounts.')
        return

    cf_template_1, cf_template_2 = create_cloudformation_template(resources_to_create, lambda_client_main, lambda_client_account_1, iam_client_main, s3_client_main, ec2_client_main, kms_client_main, iam_client_account_1, s3_client_account_1, source_account_id, destination_account_id, application_tag, lambda_code_storage_bucket)
    
    print('creating resources')
    
    if deploy:
        if cf_template_2 != 'null':
            new_template = json.dumps(cf_template_2)
            new_template = new_template.replace(source_account_id, destination_account_id)
            new_template = json.loads(new_template)
            deploy_stack(cf_client_account_2, stack_name_roles, new_template)
            #deploy_or_update_stack(cf_client_account_2, stack_name_roles, new_template, destination_account_id)
            time.sleep(10)
        
        if cf_template_1:
            deploy_stack(cf_client_account_2, stack_name_resources, cf_template_1)
            #deploy_or_update_stack(cf_client_account_2, stack_name_resources, cf_template_1, destination_account_id)"""
    else:
        if cf_template_2 != 'null':
            new_template = json.dumps(cf_template_2)
            new_template = new_template.replace(source_account_id, destination_account_id)
            new_template = json.loads(new_template)
            upload_template_to_bucket(s3_client_account_1, lambda_code_storage_bucket, new_template, app_name, stack_name_roles)
        
        if cf_template_1:
            upload_template_to_bucket(s3_client_account_1, lambda_code_storage_bucket, cf_template_1, app_name, stack_name_resources)
        
         
def create_cloudformation_template(resource_arns, lambda_client, destination_lambda_client, iam_client, s3_client, ec2_client, kms_client, destination_iam_client, destination_s3_client, source_account_id, destination_account_id, application_tag, lambda_code_storage_bucket):
    resources = {}
    iam_resources = {}
    lambda_count = 0
    log_count = 0
    kms_count = 0
    iam_policy_count = 0
    iam_role_count = 0
    ec2_count = 0
    s3_count = 0
    ops_queue = {}
    
    roles_created = []
    policies_created = []
    
    # loop through all resources in the application
    for arn in resource_arns:
        if isinstance(arn, str):
            resource_arn = arn
        else:
            resource_arn = arn['ResourceARN']
        resource_type, resource_id = resource_arn.split(':')[2], resource_arn.split('/')[-1]
        
        # TODO: create ec2 template
        if resource_type == 'ec2':
            instance_id = arn.split('/')[-1]
            ec2_details = get_ec2_instance_details(ec2_client, instance_id, iam_client) 
            resources['EC2Instance'] = {
                'Type': 'AWS::EC2::Instance',
                'Properties': ec2_details
            }
            
        elif resource_type == 's3':
            bucket_name = resource_arn.split(':::')[-1]
            s3_details = get_s3_bucket_details(s3_client, bucket_name)
            s3_bucket_name = s3_details['BucketName'] + '-' + destination_account_id
            ops_queue['s3_bucket_update'] = [bucket_name, s3_bucket_name]
            if s3_count > 0:
                resource = 'S3Bucket' + str(s3_count)
            else:
                resource = 'S3Bucket'
            resources[resource] = {
                'Type': 'AWS::S3::Bucket',
                'Properties': {
                    'BucketName': s3_bucket_name,
                    'BucketEncryption': {
                        'ServerSideEncryptionConfiguration': [
                            {
                                'ServerSideEncryptionByDefault': {
                                    'SSEAlgorithm': 'AES256'
                                }
                            }
                        ]
                    },
                    'Tags': [
                        {"Value": application_tag[1], "Key" : application_tag[0]}
                    ]
                }
            }
            
        # create lambda function, iam role/policies, and lambda log group templates and map them to their respective keys in iam_resources/resources dictionary
        elif resource_type == 'lambda':
            lambda_details = get_lambda_function_details(lambda_client, lambda_code_storage_bucket, destination_s3_client, resource_id)
            lambda_status = lambda_exists(destination_lambda_client, resource_id.split(':')[-1])
            if not lambda_status:
                for tag in lambda_details['Tags']:
                    
                    if tag['Key'] == 'awsApplication':
                        tag['Value'] = application_tag[1]
                role_name = lambda_details['Role'].split('/')[-1]
                updated_role_arn = lambda_details['Role'].replace(source_account_id, str(destination_account_id))
                lambda_details['Role'] = updated_role_arn
                if role_name not in roles_created:
                    role_properties = create_role_template(iam_client, destination_iam_client, role_name, destination_account_id)
                    if len(roles_created) > 0:
                        resource = 'IAMRole' + str(len(roles_created))
                    else:
                        resource = 'IAMRole'
                    #check if role has already been created in account
                    if not check_role_exists(destination_iam_client, role_name):
                        iam_resources[resource] = {
                            'Type': 'AWS::IAM::Role',
                            'Properties': role_properties
                        }
                        roles_created.append(role_name)
                    
                    if role_properties['ManagedPolicyArns']:
                        for policy_arn in role_properties['ManagedPolicyArns']:
                            if policy_arn not in policies_created:
                                policy_name = policy_arn.split('/')[-1]
                                if not check_policy_exists(destination_iam_client, policy_name):
                                    policy_properties = create_managed_policy_template(iam_client, role_name, policy_arn, destination_account_id)
                                    if len(policies_created) > 0:
                                        resource = 'IAMManagedPolicy' + str(len(policies_created))
                                    else:
                                        resource = 'IAMManagedPolicy'
                                    
                                    s3_bucket_arn = 'arn:aws:s3:::' + lambda_details['Code']['S3Bucket']
                                    s3_object_permissions = {
                                        'Effect': 'Allow',
                                        'Action': [
                                            's3:GetObject',
                                            's3:ListBucket'
                                        ],
                                        'Resource': [
                                            s3_bucket_arn
                                        ]
                                    }
                                    
                                    iam_resources[resource] = {
                                        'Type': 'AWS::IAM::ManagedPolicy',
                                        'Properties': policy_properties
                                    }
                                    policies_created.append(policy_arn)   
                
                if lambda_count > 0:
                    resource = 'LambdaFunction' + str(lambda_count)
                else:
                    resource = 'LambdaFunction'

                if 'Variables' in lambda_details['Environment']:
                    env_vars = lambda_details['Environment']['Variables']
                    if destination_account_id not in env_vars['Bucket']:
                            lambda_details['Environment']['Variables']['Bucket'] = env_vars['Bucket'] + '-' + destination_account_id
                    
        
                resources[resource] = {
                    'Type': 'AWS::Lambda::Function',
                    'Properties': lambda_details
                }
                
                if log_count > 0:
                    resource = 'LogsLogGroup' + str(log_count)
                else:
                    resource = 'LogsLogGroup'
                    
                resources[resource] = {
                    'Type': 'AWS::Logs::LogGroup',
                    'Properties':{
                        'LogGroupName': f"/aws/lambda/{lambda_details['FunctionName']}"
                    }
                }
                log_count+=1
                lambda_count+=1
            
        # TODO: create proper kms cf tempalte
        elif resource_type == 'kmss':
            kms_id = resource_arn.split('/')[-1]
            properties = get_kms_details(kms_client,kms_id)
            #print(properties['KeyPolicy'])
            if kms_count > 0:
                resource = 'KMSKey' + str(kms_count)
            else:
                resource = 'KMSKey'
            key_policy = json.loads(properties['KeyPolicy'])    
            key_policy = json_replacer(key_policy, source_account_id, destination_account_id)
            resources[resource] = {
                'Type': 'AWS::KMS::Key',
                'Properties': {
                    'Enabled': properties['Enabled'],
                    'Description': properties['Description'],
                    'KeyPolicy': key_policy,
                    'KeySpec': properties['KeySpec'],
                    'Tags': [{
                        'Key': application_tag[0], 
                        'Value': application_tag[1]
                        }]
                }
            }
            
    resource_keys = list(resources.keys())
    for resource in resource_keys:
        if resource.startswith('LambdaFunction'):
            if 's3_bucket_update' in ops_queue:
                original_s3_name = ops_queue['s3_bucket_update'][0]
                updated_s3_name = ops_queue['s3_bucket_update'][1]
                
                if resources[resource]['Properties']['Environment']:
                    old_env_var = resources[resource]['Properties']['Environment']['Variables']['Bucket']
                    if old_env_var == original_s3_name:
                        resources[resource]['Properties']['Environment']['Variables']['s3_bucket'] = updated_s3_name
            
    cloudformation_template = {
        'AWSTemplateFormatVersion': '2010-09-09',
        'Resources': resources
    }
    
    iam_cloudformation_template = {
        'AWSTemplateFormatVersion': '2010-09-09',
        'Resources': iam_resources
    }
    
    empty_template = {
        'AWSTemplateFormatVersion': '2010-09-09',
        'Resources': {}
    }
    
    if iam_cloudformation_template == empty_template:
        iam_cloudformation_template = None

    return json.dumps(cloudformation_template, indent=2), json.dumps(iam_cloudformation_template, indent=2)

def json_replacer(dict_, old, new):
    new_json = json.dumps(dict_)
    new_json = new_json.replace(old, new)
    new_json = json.loads(new_json)
    return new_json

# creates two tempaltes (iam, resources) and replaces source account id with destination account id in the iam template
def setup_template(resources, lambda_client, lambda_client_destination_account, iam_client, s3_client, ec2_client, kms_client, destination_iam_client, destination_s3_client, source_account_id, destination_account_id, application_tag, lambda_code_storage_bucket):
    template_body, iam_template_body = create_cloudformation_template(resources, lambda_client, lambda_client_destination_account, iam_client, s3_client, ec2_client, kms_client, destination_iam_client, destination_s3_client, source_account_id, destination_account_id, application_tag, lambda_code_storage_bucket)
    new_iam_template = json_replacer(iam_template_body, source_account_id, destination_account_id)
    return template_body, new_iam_template

def upload_template_to_bucket(s3_client, s3_bucket, template = None, app_name = None, stack_name = None):
    print("Uploading template to s3")
    if template != 'null':
        response = write_template_to_s3_bucket(s3_client, s3_bucket, template, app_name + '/' + stack_name)
    
def create_and_deploy_stack(app_name, resources, cloudformation_client,lambda_client_main, lambda_client_destination_account, iam_client_main, s3_client_main, ec2_client_main, kms_client_main, iam_client_account_1, s3_client_account_1, source_account_id, destination_account_id, application_tag, stack_name, stack_name_2, account_name, account_client, app_id, deploy, lambda_code_storage_bucket):
    template_1, template_2 = setup_template(resources, lambda_client_main, lambda_client_destination_account, iam_client_main, s3_client_main, ec2_client_main, kms_client_main, iam_client_account_1, s3_client_account_1, source_account_id, destination_account_id, application_tag, lambda_code_storage_bucket)
    if app_id:
        if deploy:
            print('Deploying')
            if template_2 != 'null':
                stack_name = deploy_stack(cloudformation_client, stack_name, template_2)
                time.sleep(15)
            stack_name_2 = deploy_stack(cloudformation_client, stack_name_2, template_1)
            if stack_name_2 and stack_name:
                time.sleep(15)
                stack_1_status = ""
                stack_2_status = ""
                try:
                    stack_1_status = cloudformation_client.describe_stacks(StackName=stack_name)['Stacks'][0]['StackStatus']
                except:
                    pass
                try:
                    stack_2_status = cloudformation_client.describe_stacks(StackName=stack_name_2)['Stacks'][0]['StackStatus']
                except:
                    pass
                if stack_1_status and stack_2_status == 'CREATE_COMPLETE':
                    print(f"Stack {stack_name.split('/')[1]} deployed successfully in {account_name}.")
                    print(f"Stack {stack_name_2.split('/')[1]} deployed successfully in {account_name}.")
            elif stack_name_2:
                stack_1_status = cloudformation_client.describe_stacks(StackName=stack_name)['Stacks'][0]['StackStatus']
                if stack_1_status == 'CREATE_COMPLETE':
                    print(f"Stack {stack_name.split('/')[1]} deployed successfully in {account_name}.")
            elif stack_name_2:
                stack_2_status = cloudformation_client.describe_stacks(StackName=stack_name_2)['Stacks'][0]['StackStatus']
                if stack_2_status == 'CREATE_COMPLETE':
                    print(f"Stack {stack_name_2.split('/')[1]} deployed successfully in {account_name}.")
                elif stack_2_status == 'CREATE_IN_PROGRESS':
                    print(f"Stack {stack_name_2.split('/')[1]} deployment in progress in {account_name}")
            else:
                print(f"Failed to deploy stack in {account_name}.")
                delete_application(account_client, app_name)
        else:
            upload_template_to_bucket(s3_client_account_1, lambda_code_storage_bucket, template_2, app_name, stack_name)
            upload_template_to_bucket(s3_client_account_1, lambda_code_storage_bucket, template_1, app_name, stack_name_2)
    else:
        print(f"Failed to create application {app_name} in {account_name}.")