import boto3
import botocore
import json
import ipaddress

class Event:
    def __init__(self, group_id="", from_port=0, to_port=0):
        self.group_id = group_id
        self.from_port = from_port
        self.to_port = to_port

# for Lambda handler
def get_event_details(event):
    e = Event()
    group = event["detail"]["requestParameters"]
    e.group_id = group["groupId"]
    e.from_port = group["ipPermissions"]["items"][0]["fromPort"]
    e.to_port = group["ipPermissions"]["items"][0]["toPort"]
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

def check_ip_range(cidr):
    network = ipaddress.IPv4Network(cidr)
    return network.num_addresses >= 256

def remediate(client, group_id, from_port, to_port, port_no, cidr):
    group = get_group_info(client, group_id)
    if not group:
        return "Security Group Error"
    if not check_ip_range(cidr):
        return "Less than 256 IP addresses"
    try:
        if check_port(from_port, to_port, port_no) and check_ip_range(cidr):
            client.revoke_security_group_ingress(
                CidrIp=cidr,     # 172.31.0.0/16 in EC2?
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
    remediate(ec2_client, e.group_id, e.from_port, e.to_port, 22, "172.31.0.0/16")
    remediate(ec2_client, e.group_id, e.from_port, e.to_port, 3389, "172.31.0.0/16")
    group_info = get_group_info(ec2_client, e.group_id)
    print(group_info)
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }