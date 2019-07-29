
import boto3
import gzip
import json
import logging
import datetime
import time
from os import environ
from ipaddress import ip_address
from botocore.config import Config
from urllib.parse import unquote_plus
from urllib.request import Request, urlopen
from urllib.parse import urlparse

logging.getLogger().debug('Loading function')

# ======================================================================================================================
# Constants/Globals
# ======================================================================================================================
API_CALL_NUM_RETRIES = 5

waf = None
config = {}


# ======================================================================================================================
# DynamoDB
# ======================================================================================================================
def write_to_dynamo(ip_set_id, outstanding_requesters):
    try:
        logging.getLogger().info("[write_to_dynamo] \twrite to dynamo table in region %s" % environ['REGION'])
        dynamodb = boto3.resource('dynamodb', region_name=environ['REGION'])
        table = dynamodb.Table('abused_correlation_ids')

        # --------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[write_to_dynamo] \tMerge general and uriList into a single list")
        # --------------------------------------------------------------------------------------------------------------
        unified_outstanding_requesters = outstanding_requesters['general']
        for uri in outstanding_requesters['uriList'].keys():
            for k in outstanding_requesters['uriList'][uri].keys():
                if (k not in unified_outstanding_requesters.keys() or
                        outstanding_requesters['uriList'][uri][k]['max_counter_per_min'] >
                        unified_outstanding_requesters[k]['max_counter_per_min']):
                    unified_outstanding_requesters[k] = outstanding_requesters['uriList'][uri][k]
        logging.getLogger().info("[process_log_file] \tUpdate correlation_id set %s", unified_outstanding_requesters)

        for k in unified_outstanding_requesters.keys():
            logging.getLogger().info("[update_waf_ip_set] \tBlock remaining outstanding requesters (%s)" % k)

            response = table.put_item(
                Item = {
                    'correlation_id': k,
                    'updated_at': unified_outstanding_requesters[k]['updated_at'],
                    'max_counter_per_min': unified_outstanding_requesters[k]['max_counter_per_min'],
                }
            )
            print("PutItem succeeded:")
            print(json.dumps(response))

    except Exception as e:
        logging.getLogger().error("[write_to_dynamo] \terror write to dynamo")


# ======================================================================================================================
# Lambda Log Parser
# ======================================================================================================================
def load_configurations(bucket_name, key_name):
    logging.getLogger().debug('[load_configurations] Start')

    try:
        s3 = boto3.resource('s3')
        file_obj = s3.Object(bucket_name, key_name)
        file_content = file_obj.get()['Body'].read()

        global config
        config = json.loads(file_content)

    except Exception as e:
        logging.getLogger().error("[load_configurations] \tError to read config file")
        raise e

    logging.getLogger().debug('[load_configurations] End')


def get_outstanding_requesters(bucket_name, key_name, log_type):
    logging.getLogger().debug('[get_outstanding_requesters] Start')

    correlation_id_counter = {
        'general': {},
        'uriList': {}
    }

    correlation_id_outstanding_requesters = {
        'general': {},
        'uriList': {}
    }

    try:
        # --------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[get_outstanding_requesters] \tDownload file from S3")
        # --------------------------------------------------------------------------------------------------------------
        local_file_path = '/tmp/' + key_name.split('/')[-1]
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, key_name, local_file_path)

        # --------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[get_outstanding_requesters] \tRead file content")
        # --------------------------------------------------------------------------------------------------------------
        with gzip.open(local_file_path, 'r') as content:
            for line in content:
                try:
                    request_key = ""
                    request_by_correlation_id_key = ""
                    uri = ""
                    return_code_index = None

                    if log_type == 'waf':
                        line = line.decode()  # Remove the b in front of each field
                        line_data = json.loads(str(line))

                        request_by_correlation_id_key = datetime.datetime.fromtimestamp(int(line_data['timestamp']) / 1000.0).isoformat(
                            sep='T', timespec='minutes')

                        uri = urlparse(line_data['httpRequest']['uri']).path
                        header_list = line_data['httpRequest']['headers']
                        for x in header_list:
                            if x['name'] == 'x-i2g-correlation-id':
                                request_by_correlation_id_key += ' ' + x['value']
                                logging.getLogger().info("[get_outstanding_requesters] \t\t item correlation_id: %s %s" % (x['value'], request_by_correlation_id_key))
                                break

                    else:
                        return correlation_id_counter

                    if 'ignoredSufixes' in config['general'] and uri.endswith(
                            tuple(config['general']['ignoredSufixes'])):
                        logging.getLogger().debug(
                            "[get_outstanding_requesters] \t\tSkipping line %s. Included in ignoredSufixes." % line)
                        continue

                    if return_code_index == None or line_data[return_code_index] in config['general']['errorCodes']:
                        if request_by_correlation_id_key is not None:
                            if request_by_correlation_id_key in correlation_id_counter['general'].keys():
                                correlation_id_counter['general'][request_by_correlation_id_key] += 1
                            else:
                                correlation_id_counter['general'][request_by_correlation_id_key] = 1

                        if 'uriList' in config and uri in config['uriList'].keys():
                            if uri not in correlation_id_counter['uriList'].keys():
                                correlation_id_counter['uriList'][uri] = {}

                            if request_key in correlation_id_counter['uriList'][uri].keys():
                                correlation_id_counter['uriList'][uri][request_key] += 1
                            else:
                                correlation_id_counter['uriList'][uri][request_key] = 1

                except Exception as e:
                    logging.getLogger().error("[get_outstanding_requesters] \t\tError to process line: %s" % line)

        # --------------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[get_outstanding_requesters] \tKeep only outstanding requesters")
        # --------------------------------------------------------------------------------------------------------------
        threshold = 'requestThreshold' if log_type == 'waf' else "errorThreshold"
        utc_now_timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z%z")
        for k, num_reqs in correlation_id_counter['general'].items():
            try:
                k = k.split(' ')[-1]
                logging.getLogger().info("[get_outstanding_requesters] \t\tgeneral (%s) %s %s" % (uri, k, num_reqs))
                if num_reqs >= 5:
                    logging.getLogger().info(
                        "[get_outstanding_requesters] \t\tfound more than threshold (%s) %s %s" % (uri, k, num_reqs))
                    if k not in correlation_id_outstanding_requesters['general'].keys() or num_reqs > \
                            correlation_id_outstanding_requesters['general'][k]['max_counter_per_min']:
                        logging.getLogger().info(
                            "[get_outstanding_requesters] \t\t send to outsanding requester (%s) %s %s" % (
                                uri, k, num_reqs))
                        correlation_id_outstanding_requesters['general'][k] = {
                            'max_counter_per_min': num_reqs,
                            'updated_at': utc_now_timestamp_str
                        }
            except Exception as e:
                logging.getLogger().error(
                    "[get_outstanding_requesters] \t\tError to process outstanding requester: %s" % k)

    except Exception as e:
        logging.getLogger().error("[get_outstanding_requesters] \tError to read input file")
        logging.getLogger().error(e)

    logging.getLogger().debug('[get_outstanding_requesters] End')
    return correlation_id_outstanding_requesters


def merge_outstanding_requesters(bucket_name, key_name, log_type, output_key_name, outstanding_requesters):
    logging.getLogger().debug('[merge_outstanding_requesters] Start')

    force_update = False
    s3 = boto3.client('s3')

    # --------------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[merge_outstanding_requesters] \tCalculate Last Update Age")
    # --------------------------------------------------------------------------------------------------------------
    response = None
    try:
        response = s3.head_object(Bucket=bucket_name, Key=output_key_name)
    except Exception:
        logging.getLogger().info('[merge_outstanding_requesters] No file to be merged.')
        need_update = True
        return outstanding_requesters, need_update

    utc_last_modified = response['LastModified'].astimezone(datetime.timezone.utc)
    utc_now_timestamp = datetime.datetime.now(datetime.timezone.utc)

    utc_now_timestamp_str = utc_now_timestamp.strftime("%Y-%m-%d %H:%M:%S %Z%z")
    last_update_age = int(((utc_now_timestamp - utc_last_modified).total_seconds()) / 60)

    # --------------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[merge_outstanding_requesters] \tDownload current blocked IPs")
    # --------------------------------------------------------------------------------------------------------------
    local_file_path = '/tmp/' + key_name.split('/')[-1] + '_REMOTE.json'
    s3.download_file(bucket_name, output_key_name, local_file_path)

    # ----------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[merge_outstanding_requesters] \tProcess outstanding requesters files")
    # ----------------------------------------------------------------------------------------------------------
    remote_outstanding_requesters = {
        'general': {},
        'uriList': {}
    }
    with open(local_file_path, 'r') as file_content:
        remote_outstanding_requesters = json.loads(file_content.read())

    threshold = 'requestThreshold' if log_type == 'waf' else "errorThreshold"
    try:
        if 'general' in remote_outstanding_requesters:
            for k, v in remote_outstanding_requesters['general'].items():
                try:
                    if k in outstanding_requesters['general'].keys():
                        logging.getLogger().info(
                            "[merge_outstanding_requesters] \t\tUpdating general data of BLOCK %s rule" % k)
                        outstanding_requesters['general'][k]['updated_at'] = utc_now_timestamp_str
                        if v['max_counter_per_min'] > outstanding_requesters['general'][k]['max_counter_per_min']:
                            outstanding_requesters['general'][k]['max_counter_per_min'] = v['max_counter_per_min']

                    else:
                        utc_prev_updated_at = datetime.datetime.strptime(v['updated_at'],
                                                                         "%Y-%m-%d %H:%M:%S %Z%z").astimezone(
                            datetime.timezone.utc)
                        total_diff_min = ((utc_now_timestamp - utc_prev_updated_at).total_seconds()) / 60

                        if v['max_counter_per_min'] < config['general'][threshold]:
                            force_update = True
                            logging.getLogger().info(
                                "[merge_outstanding_requesters] \t\t%s is bellow the current general threshold" % k)

                        elif total_diff_min < config['general']['blockPeriod']:
                            logging.getLogger().debug("[merge_outstanding_requesters] \t\tKeeping %s in general" % k)
                            outstanding_requesters['general'][k] = v

                        else:
                            force_update = True
                            logging.getLogger().info("[merge_outstanding_requesters] \t\t%s expired in general" % k)

                except Exception:
                    logging.getLogger().error("[merge_outstanding_requesters] \tError merging general %s rule" % k)
    except Exception:
        logging.getLogger().error('[merge_outstanding_requesters] Failed to process general group.')

    try:
        if 'uriList' in remote_outstanding_requesters:
            if 'uriList' not in config or len(config['uriList']) == 0:
                force_update = True
                logging.getLogger().info(
                    "[merge_outstanding_requesters] \t\tCurrent config file does not contain uriList anymore")
            else:
                for uri in remote_outstanding_requesters['uriList'].keys():
                    if 'ignoredSufixes' in config['general'] and uri.endswith(
                            tuple(config['general']['ignoredSufixes'])):
                        force_update = True
                        logging.getLogger().info(
                            "[merge_outstanding_requesters] \t\t%s is in current ignored sufixes list." % uri)
                        continue

                    for k, v in remote_outstanding_requesters['uriList'][uri].items():
                        try:
                            if uri in outstanding_requesters['uriList'].keys() and k in \
                                    outstanding_requesters['uriList'][uri].keys():
                                logging.getLogger().info(
                                    "[merge_outstanding_requesters] \t\tUpdating uriList (%s) data of BLOCK %s rule" % (
                                    uri, k))
                                outstanding_requesters['uriList'][uri][k]['updated_at'] = utc_now_timestamp_str
                                if v['max_counter_per_min'] > outstanding_requesters['uriList'][uri][k][
                                    'max_counter_per_min']:
                                    outstanding_requesters['uriList'][uri][k]['max_counter_per_min'] = v[
                                        'max_counter_per_min']

                            else:
                                utc_prev_updated_at = datetime.datetime.strptime(v['updated_at'],
                                                                                 "%Y-%m-%d %H:%M:%S %Z%z").astimezone(
                                    datetime.timezone.utc)
                                total_diff_min = ((utc_now_timestamp - utc_prev_updated_at).total_seconds()) / 60

                                if v['max_counter_per_min'] < config['uriList'][uri][threshold]:
                                    force_update = True
                                    logging.getLogger().info(
                                        "[merge_outstanding_requesters] \t\t%s is bellow the current uriList (%s) "
                                        "threshold" % (k, uri))

                                elif total_diff_min < config['general']['blockPeriod']:
                                    logging.getLogger().debug(
                                        "[merge_outstanding_requesters] \t\tKeeping %s in uriList (%s)" % (k, uri))

                                    if uri not in outstanding_requesters['uriList'].keys():
                                        outstanding_requesters['uriList'][uri] = {}

                                    outstanding_requesters['uriList'][uri][k] = v
                                else:
                                    force_update = True
                                    logging.getLogger().info(
                                        "[merge_outstanding_requesters] \t\t%s expired in uriList (%s)" % (k, uri))

                        except Exception:
                            logging.getLogger().error(
                                "[merge_outstanding_requesters] \tError merging uriList (%s) %s rule" % (uri, k))
    except Exception:
        logging.getLogger().error('[merge_outstanding_requesters] Failed to process uriList group.')

    need_update = (force_update or
                   last_update_age > int(environ['MAX_AGE_TO_UPDATE']) or
                   len(outstanding_requesters['general']) > 0 or
                   len(outstanding_requesters['uriList']) > 0)

    logging.getLogger().debug('[merge_outstanding_requesters] End')
    return outstanding_requesters, need_update


def write_output(bucket_name, key_name, output_key_name, outstanding_requesters):
    logging.getLogger().debug('[write_output] Start')

    try:
        current_data = '/tmp/' + key_name.split('/')[-1] + '_LOCAL.json'
        with open(current_data, 'w') as outfile:
            json.dump(outstanding_requesters, outfile)

        s3 = boto3.client('s3')
        s3.upload_file(current_data, bucket_name, output_key_name, ExtraArgs={'ContentType': "application/json"})

    except Exception as e:
        logging.getLogger().error("[write_output] \tError to write output file")
        logging.getLogger().error(e)

    logging.getLogger().debug('[write_output] End')


def process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, ip_set_id):
    logging.getLogger().debug('[process_log_file] Start')

    # --------------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[process_log_file] \tReading input data and get outstanding requesters")
    # --------------------------------------------------------------------------------------------------------------
    load_configurations(bucket_name, conf_filename)
    outstanding_requesters = get_outstanding_requesters(bucket_name, key_name, log_type)

    # --------------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[process_log_file] \t outstanding requester before merge %s", outstanding_requesters)
    # --------------------------------------------------------------------------------------------------------------

    outstanding_requesters, need_update = merge_outstanding_requesters(bucket_name, key_name, log_type, output_filename,
                                                                       outstanding_requesters)

    # --------------------------------------------------------------------------------------------------------------
    logging.getLogger().info("[process_log_file] \t outstanding requester after merge %s", outstanding_requesters)
    # --------------------------------------------------------------------------------------------------------------

    if need_update:
        # ----------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[process_log_file] \tUpdate new blocked requesters list to %s", outstanding_requesters)
        # ----------------------------------------------------------------------------------------------------------
        write_output(bucket_name, key_name, output_filename, outstanding_requesters)
        write_to_dynamo(ip_set_id, outstanding_requesters)
    else:
        # ----------------------------------------------------------------------------------------------------------
        logging.getLogger().info("[process_log_file] \tNo changes identified")
        # ----------------------------------------------------------------------------------------------------------

    logging.getLogger().debug('[process_log_file] End')


# ======================================================================================================================
# Lambda Entry Point
# ======================================================================================================================
def lambda_handler(event, context):
    logging.getLogger().debug('[lambda_handler] Start')

    result = {}
    try:
        # ------------------------------------------------------------------
        # Set Log Level
        # ------------------------------------------------------------------
        global log_level
        log_level = str(environ['LOG_LEVEL'].upper())
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            log_level = 'ERROR'
        logging.getLogger().setLevel(log_level)

        # ------------------------------------------------------------------
        # Set WAF API Level
        # ------------------------------------------------------------------
        global waf
        if environ['LOG_TYPE'] == 'alb':

            session = boto3.session.Session(region_name=environ['REGION'])
            waf = session.client('waf-regional', config=Config(retries={'max_attempts': API_CALL_NUM_RETRIES}))
        else:
            print('waf log type')
            waf = boto3.client('waf', config=Config(retries={'max_attempts': API_CALL_NUM_RETRIES}))

        # ----------------------------------------------------------
        # Process event
        # ----------------------------------------------------------
        logging.getLogger().info('[main] received event', event)
        if 'Records' in event:
            for r in event['Records']:
                bucket_name = r['s3']['bucket']['name']
                key_name = unquote_plus(r['s3']['object']['key'])

                if 'WAF_ACCESS_LOG_BUCKET' in environ and bucket_name == environ['WAF_ACCESS_LOG_BUCKET']:
                    conf_filename = environ['STACK_NAME'] + '-waf_log_conf.json'
                    output_filename = environ['STACK_NAME'] + '-waf_log_out.json'
                    log_type = 'waf'
                    ip_set_id = environ['IP_SET_ID_HTTP_FLOOD']
                    process_log_file(bucket_name, key_name, conf_filename, output_filename, log_type, ip_set_id)
                    result['message'] = "[lambda_handler] AWS WAF access log file processed."
                    logging.getLogger().debug(result['message'])

                else:
                    result['message'] = "[lambda_handler] undefined handler for bucket %s" % bucket_name
                    logging.getLogger().info(result['message'])

        else:
            result['message'] = "[lambda_handler] undefined handler for this type of event"
            logging.getLogger().info(result['message'])

    except Exception as error:
        logging.getLogger().error(str(error))

    logging.getLogger().debug('[lambda_handler] End')
    return result
