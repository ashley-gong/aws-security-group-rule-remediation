import boto3
import botocore
import json

class Event:
    def __init__(self, group_id=""):
        self.group_id = group_id

# for Lambda handler
def get_event_details(event):
    e = Event()
    group_id = event["detail"]["requestParameters"]["groupId"]
    e.group_id = group_id
    return e

# describe security group
def get_group_info(client, group_id):
    try:
        res = client.describe_security_groups(GroupIds=[group_id])
        return res
    except botocore.exceptions.ClientError as error:
        print(error.response['Error']['Code'])
        return

def check_port(from_port, to_port, port_no):
    return port_no >= from_port and from_port <= to_port

def remediate(client, group_id, from_port, to_port, port_no):
    group = get_group_info(client, group_id)
    if not group:
        return "Security Group Error"
    try:
        client.revoke_security_group_ingress(
            CidrIp='0.0.0.0/0',     # 172.31.0.0/16 in EC2?
            FromPort=from_port,
            GroupId=group_id,
            ToPort=to_port,
            IpProtocol='tcp')
        
    except botocore.exceptions.ClientError as error:
        return error.response['Error']['Code']
    
def lambda_handler(event, context):
    print(event)
    e = get_event_details(event)
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    remediate(ec2_client, e.group_id, 22)
    remediate(ec2_client, e.group_id, 3389)
    group_info = get_group_info(ec2_client, e.group_id)
    print(group_info)
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }