import boto3
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
    res = client.describe_security_groups(GroupIds=[group_id])
    return res

def remediate(client, group_id, port_no):
    group = get_group_info(client, group_id)
    rule = {'CidrIp': '0.0.0.0/0'}
    
    # Assuming only 1 security group - could add nested for loop
    for i in group["SecurityGroups"][0]["IpPermissions"]:
        if i['FromPort'] == port_no and rule not in i["IpRanges"]:
            print('ok')
            return

    client.revoke_security_group_ingress(
        CidrIp='0.0.0.0/0',     # 172.31.0.0/16 in EC2?
        FromPort=port_no,
        GroupId=group_id,
        ToPort=port_no,
        IpProtocol='tcp')
    
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