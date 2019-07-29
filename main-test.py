from main import lambda_handler
import settings
import logging
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)


def test_simple_event():
    record = {'Records': [{'eventVersion': '2.1', 'eventSource': 'aws:s3', 'awsRegion': 'us-east-1',
                           'eventTime': '2019-07-26T04:42:12.870Z', 'eventName': 'ObjectCreated:Put',
                           'userIdentity': {'principalId': 'AWS:AROATTCRBLUWT5FNY52QN:AWSFirehoseToS3'},
                           'requestParameters': {'sourceIPAddress': '3.84.239.21'},
                           'responseElements': {'x-amz-request-id': '9B9322B197D30E18',
                                                'x-amz-id-2': 'Cth5SSzqWPMzHibJ25AgXZcMs+ojD3C4l4MUAbOfspKRD6vf0MJ+02taoZPpsBcRLaN+OVw+lJo='},
                           's3': {'s3SchemaVersion': '1.0', 'configurationId': 'Call Log Parser',
                                  'bucket': {'name': 'waf-autobot-waflogbucket-1uoczbjdq1nxf',
                                             'ownerIdentity': {'principalId': 'A34ROINPPVRDOV'},
                                             'arn': 'arn:aws:s3:::waf-autobot-waflogbucket-1uoczbjdq1nxf'}, 'object': {
                                   'key': 'AWSLogs/2019/07/26/04/aws-waf-logs-wafautobot_BmsvvM-1-2019-07-26-04-37-11-11e9ddf7-c674-4963-973c-6bbdd35c67aa.gz',
                                   'size': 710, 'eTag': '7a989b9af65e43ab6216fedfa95c5978',
                                   'sequencer': '005D3A84A4C6F703F4'}}}]}
    lambda_handler(record, 1)



