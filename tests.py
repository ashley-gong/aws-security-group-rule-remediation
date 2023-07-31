import boto3
from moto import mock_ec2
from remediation import remediate, get_group_info

@mock_ec2
def test_1():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test1',
        Description='Port 22 open to 0.0.0.0/0 - rule should be revoked',
        VpcId='' # what is my vpc ID?
    )

    security_group_id = response['GroupId']

    # Authorize security group ingress
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
    ])

    ans = remediate(ec2_client, security_group_id, 22)
    assert(ans == None)
    res = get_group_info(ec2_client, security_group_id)
    print(res)

test_1()

@mock_ec2
def test_2():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test1',
        Description='Port 3389 open to 0.0.0.0/0 - rule should be revoked',
    )

    security_group_id = response['GroupId']

    # Authorize security group ingress
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 3389,
             'ToPort': 3389,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
    ])

    ans = remediate(ec2_client, security_group_id, 3389)
    assert(ans == None)
    res = get_group_info(ec2_client, security_group_id)
    print(res)


test_2()

# how to check if rule does not exist
@mock_ec2
def test_3():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test1',
        Description='Port 3389 open to 10.0.0.0/8 - rule not revoked',
    )

    security_group_id = response['GroupId']

    # Authorize security group ingress
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 3389,
             'ToPort': 3389,
             'IpRanges': [{'CidrIp': '10.0.0.0/8'}]},
    ])

    ans = remediate(ec2_client, security_group_id, 3389)
    assert(ans == None)

test_3()