import boto3
from moto import mock_ec2
from remediation import remediate

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
             'IpRanges': [{'CidrIp': '172.31.0.0/16'}]},
    ])

    ans = remediate(ec2_client, security_group_id, 22)
    assert(ans == None)

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
             'IpRanges': [{'CidrIp': '172.31.0.0/16'}]},
    ])

    ans = remediate(ec2_client, security_group_id, 3389)
    assert(ans == None)

test_2()