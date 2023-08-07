import boto3
from moto import mock_ec2
from remediation import remediate, get_group_info

# Revoke Port 22 ingress - within range
@mock_ec2
def test_1():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test1',
        Description='Port 22 open to 0.0.0.0/0 - rule should be revoked',
    )

    security_group_id = response['GroupId']

    # Authorize security group ingress
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 21,
             'ToPort': 23,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}]},
    ])

    ans = remediate(ec2_client, security_group_id, 21, 23, 22, '0.0.0.0/0')
    assert(ans == None)
    print(get_group_info(ec2_client, security_group_id))

test_1()

# Revoke Port 3389 ingress
@mock_ec2
def test_2():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test2',
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

    ans = remediate(ec2_client, security_group_id, 3389, 3389, 3389, '0.0.0.0/0')
    assert(ans == None)
    print(get_group_info(ec2_client, security_group_id))

test_2()

# Do not revoke valid Port 3389 ingress
@mock_ec2
def test_3():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test3',
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

    ans = remediate(ec2_client, security_group_id, 3389, 3389, 3389, '0.0.0.0/0')
    assert(ans == 'InvalidPermission.NotFound')
    print(get_group_info(ec2_client, security_group_id))

test_3()

# Only revoke offending Port 22 ingress
@mock_ec2
def test_4():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test4',
        Description='Port 22 open to 0.0.0.0/0 and 10.0.0.0/8',
    )

    security_group_id = response['GroupId']

    # Authorize security group ingress
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}, {'CidrIp': '10.0.0.0/8'}]},
    ])

    ans = remediate(ec2_client, security_group_id, 22, 22, 22, '0.0.0.0/0')
    assert(ans == None)
    print(get_group_info(ec2_client, security_group_id))

test_4()

# Revoke both Port 22 and Port 3389 invalid ingress, keep Port 22 valid ingress
@mock_ec2
def test_5():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test5',
        Description='Port 22 and 3389 open to 0.0.0.0/0',
    )

    security_group_id = response['GroupId']

    # Authorize security group ingress
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}, {'CidrIp': '10.0.0.0/8'}]},
             {'IpProtocol': 'tcp',
              'FromPort': 3387,
              'ToPort': 3390,
              'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
    ])

    ans = remediate(ec2_client, security_group_id, 22, 22, 22, '0.0.0.0/0')
    ans2 = remediate(ec2_client, security_group_id, 3387, 3390, 3389, '0.0.0.0/0')
    assert(ans == None)
    assert(ans2 == None)
    print(get_group_info(ec2_client, security_group_id))

test_5()

# Error catch if security group no longer exists
@mock_ec2
def test_6():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test5',
        Description='Port 22 and 3389 open to 0.0.0.0/0',
    )

    security_group_id = response['GroupId']

    # Authorize security group ingress
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'IpRanges': [{'CidrIp': '0.0.0.0/0'}, {'CidrIp': '10.0.0.0/8'}]},
    ])

    ec2_client.delete_security_group(
        GroupId=security_group_id
    )

    ans = remediate(ec2_client, security_group_id, 22, 22, 22, '0.0.0.0/0')
    assert(ans == "Security Group Error")
    print(ans)

test_6()

# Revoke Port 22 ingress - less than 256 addresses, won't revoke
@mock_ec2
def test_7():
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    
    # Create security group
    response = ec2_client.create_security_group(
        GroupName='Test7',
        Description='Port 22 open to 152.2.136.0/26 - rule should not be revoked',
    )

    security_group_id = response['GroupId']

    # Authorize security group ingress
    ec2_client.authorize_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            {'IpProtocol': 'tcp',
             'FromPort': 21,
             'ToPort': 23,
             'IpRanges': [{'CidrIp': '152.2.136.0/26'}]},
    ])

    ans = remediate(ec2_client, security_group_id, 21, 23, 22, '152.2.136.0/26')
    assert(ans == "Less than 256 IP addresses")
    print(ans)

test_7()