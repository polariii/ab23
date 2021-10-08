import boto3
import math
import json
import time
import datetime
import ipaddress
from boto3.dynamodb.conditions import Key, Attr
from os import environ

# Get the service resource.
dynamodb = boto3.resource('dynamodb', region_name=environ['DYNAMODB_REGION'])
table = dynamodb.Table(environ['DYNAMODB_TABLE'])
table_blocked = dynamodb.Table(environ['DYNAMODB_TABLE_BLOCKED_IPS'])

# WAF
waf = boto3.client('wafv2')
API_CALL_NUM_RETRIES = 3

def valid_IPV4(ip):
    if ipaddress.ip_address(ip).version == 4:
        return True
    else:
        return False
        

def waf_get_ip_set(ip_set_id, ip_set_name):
    response = None
    
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_ip_set(Id=ip_set_id, Name=ip_set_name, Scope='CLOUDFRONT')
        except Exception as e:
            print(e)
            delay = math.pow(2, attempt)
            print("[waf_get_ip_set] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[waf_get_ip_set] Failed ALL attempts to call API")

    return response

def get_ipset_lock_token(ip_set_id, ip_set_name):

    ip_set = waf.get_ip_set(
        Name=ip_set_name,
        Scope='CLOUDFRONT',
        Id=ip_set_id)
    return ip_set['LockToken']


    
    
def waf_update_ip_set(ip_set_id, ip_set_name, updates_list):
    response = None
    
    lock_token = get_ipset_lock_token(ip_set_id, ip_set_name)

    if updates_list != []:
        for attempt in range(API_CALL_NUM_RETRIES):
            try:
                response = waf.update_ip_set(Id=ip_set_id, Name='ato-bot', Scope='CLOUDFRONT',
                        LockToken=lock_token,
                        Addresses=updates_list)
                            
            except Exception as e:
                print(e)
                delay = math.pow(2, attempt)
                print("[waf_update_ip_set] Retrying in %d seconds..." % (delay))
                time.sleep(delay)
            else:
                break
        else:
            print("[waf_update_ip_set] Failed ALL attempts to call API")

    return response


def lambda_handler(event, context):
    IPS_REMOVE_WAF = []
    
    try:
        print('------ CLEARING IPs in log DYNAMODB -------------')
        timestamp_removed_dynamodb=int(datetime.datetime.now().timestamp())-int(environ['TIME_HISTORY_DYNAMODB'])

        response = table.scan(
            IndexName='TIMESTAMP',
            FilterExpression=Attr('TIMESTAMP').lte(timestamp_removed_dynamodb)
        )
        
        
        count_removed_logs=len(response['Items'])
        
        print ('Deleting %s logs older than %s seconds from DYNAMODB.'%(count_removed_logs, str(environ['TIME_HISTORY_DYNAMODB'])))
        
        if count_removed_logs > 0:
            for k in response['Items']:
                table.delete_item(
                    Key={'ID': k['ID']}
                )
                
        print('------ CLEARING IPs IN WAF -------------')
        timestamp_removed_dynamodb=int(datetime.datetime.now().timestamp())-int(environ['TIME_IP_BLOCKED_WAF'])

        response = table_blocked.scan(
            IndexName='TIMESTAMP',
            FilterExpression=Attr('TIMESTAMP').lte(timestamp_removed_dynamodb)
        )
       

        count_removed_waf=len(response['Items'])
        
        if environ['IP_SET_ID_AUTO_BLOCK'] != None:
            response_waf = waf_get_ip_set(environ['IP_SET_ID_AUTO_BLOCK'], environ['WAF_IP_SET_NAME'])

            all_ip_set = response_waf['IPSet']["Addresses"]
            # set(all_ip_set) - response
            delete_ip_set = [i["IP"]+'/32' for i in response["Items"]]

            new_ip_set = [i for i in all_ip_set if i not in delete_ip_set]
            
            lock_token = get_ipset_lock_token('bd1d1fcd-d73c-4bff-a66b-5f58f529df14')

            response = waf.update_ip_set(environ['IP_SET_ID_AUTO_BLOCK'], environ['WAF_IP_SET_NAME'], new_ip_set)
            
        
            for ip in delete_ip_set:
                print(ip)
                table_blocked.delete_item(
                    Key={'IP': ip[:-3]}
                    )
        
        return True
    except Exception as e:
        print(e)
        