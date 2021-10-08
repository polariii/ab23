import json
import boto3
import math
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


def check_ip_blocked_dynamodb(ip):
    response = None
    
    try:
        response = table_blocked.get_item(
            Key={
                'IP': ip
            }
        )
    except Exception as e:
        print(e)
        print("Error querying IP (%s) in blocked IPs table"%ip)

    if len(response) > 1:
        return True
    else:
        return False
    
    
def insert_ip_blocked_dynamodb(ip):
    try:
        print("Inserting IP (%s) in blocked IPs table!" % (ip))
        datetime_blocked = datetime.datetime.now()
        timestamp_blocked = int(datetime_blocked.timestamp())
        
        response = table_blocked.put_item(
           Item={
                'IP': ip,
                'DATETIME': str(datetime_blocked),
                'TIMESTAMP': timestamp_blocked
            }
        )
    except Exception as e:
        print(e)
        print("Error inserting IP (%s) in blocked IPs table!" % (ip))
    

def waf_get_ip_set(ip_set_id, ip_set_name):
    response = None

    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_ip_set(Id=ip_set_id, Name='ato-bot', Scope='CLOUDFRONT')
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
    """Returns the AWS WAF IP set lock token"""
    ip_set = waf.get_ip_set(
        Name=ip_set_name,
        Scope='CLOUDFRONT',
        Id=ip_set_id)
    return ip_set['LockToken']

    

def waf_update_ip_set(ip_set_id, ip_set_name, updates_list, ip_block):
    response = None

    lock_token = get_ipset_lock_token(ip_set_id, ip_set_name)
    
    if updates_list != []:
        for attempt in range(API_CALL_NUM_RETRIES):
            try:
                print("Inserting IP (%s) into WAF block list!" % (ip_block))
                response = waf.update_ip_set(Id=ip_set_id, Name=ip_set_name, Scope='CLOUDFRONT',
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
    JSON_IP_BLOCK = []
    
    for record in event['Records']:
        if record['eventName'] == 'INSERT':
            timestamp = record['dynamodb']['NewImage']['TIMESTAMP']['N']
            
            if valid_IPV4(record['dynamodb']['NewImage']['CLIENTIP']['S']):
                clientip = record['dynamodb']['NewImage']['CLIENTIP']['S']
            else:
                print("Formatando IPV6 (%s)" % (record['dynamodb']['NewImage']['CLIENTIP']['S']))
                clientip=str(ipaddress.ip_address(record['dynamodb']['NewImage']['CLIENTIP']['S']).exploded)
                
            timestamp_menos_time_block = int(timestamp) - int(environ['TIME_CHECK_BLOCK'])

            print('<------------------------->')
            print('Timestamp: ' + timestamp)
            print('Timestamp menos time: ' + str(timestamp_menos_time_block))
            print('ClientIP: ' + clientip)

            try:
                if not check_ip_blocked_dynamodb(clientip):
                    response = table.scan(
                        IndexName='CLIENTIPAndTIMESTAMP',
                        FilterExpression=Attr('TIMESTAMP').gte(timestamp_menos_time_block) & Attr('CLIENTIP').eq(clientip)
                    )
                    
                    count_items = len(response['Items'])
        
                    print('Number of logs in the last (' + str(environ['TIME_CHECK_BLOCK']) + 's): ' + str(count_items))
        
                    if count_items >= int(environ['COUNT_BLOCK']):
                        print('Checking if IP (' + str(clientip) + ') is already on the block list.')
                        exist_ip = False
                        

                        if check_ip_blocked_dynamodb(clientip):
                            exist_ip = True
                            print('IP (' + str(clientip) + ') is already on the DYNAMODB block list!')

                        '''
                        else:  
                            # Double check. If not exist in DynamoDB, check list WAF
                            try:
                                if environ['IP_SET_ID_AUTO_BLOCK'] != None:
                                    response_waf = waf_get_ip_set(environ['IP_SET_ID_AUTO_BLOCK'], environ['WAF_IP_SET_NAME'])
                                    all_ip_set = response_waf['IPSet']["Addresses"]
            
                                    if response != None:
                                        for k in all_ip_set:
                                            if k.split('/')[0] == clientip:
                                                exist_ip = True
                                                print('IP (' + str(clientip) + ') is already on the WAF block list!')
                                                
                                                insert_ip_blocked_dynamodb(clientip)
                            except Exception as e:
                                print('Error getting list of already blocked IPs')
                                print(e)
                        '''
                            
                        if not exist_ip: 
                            if valid_IPV4(clientip):
                                ip_type = 'IPV4'
                                mask = '32'
                                ip_block=clientip
                            else:
                                ip_type = 'IPV6'
                                mask = '128'
                                ip_block=clientip
                                
                            print('IP (' + str(ip_block) + ') will be blocked for having (' + str(environ['COUNT_BLOCK']) + ') or more failed attempts in the past (' + str(environ['TIME_CHECK_BLOCK']) + 's)')
                            
                            response_waf = waf_get_ip_set(environ['IP_SET_ID_AUTO_BLOCK'], environ['WAF_IP_SET_NAME'])

                            all_ip_set = response_waf['IPSet']["Addresses"]


                            all_ip_set.append(ip_block +'/32')
                            JSON_IP_BLOCK = all_ip_set

                            try:
                                waf_update_ip_set(environ['IP_SET_ID_AUTO_BLOCK'], environ['WAF_IP_SET_NAME'], JSON_IP_BLOCK,ip_block)
                                insert_ip_blocked_dynamodb(ip_block)  
                            except Exception as e:
                                print('Error executing IP insert function in WAF')
                                print(e)
                  
                    print('>-------------------------<')   
                else:
                    print('IP (' + str(clientip) + ') already on the DYNAMODB block list!')

            except Exception as e:
                print(e)
