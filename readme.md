```$xslt
fetch log
analyze and check if one_ip > threshold
    set to outstanding_requesters
```

## TODO
```$xslt
- understand the outstanding block and merge outstanding block
- parse correlation_id
- identify blocked correlation_id 
- update blocked correlation_id to S3
- analyze log based on URL list and error code
```


Test Data
```$xslt

line_data = {'timestamp': 1564111528734, 'formatVersion': 1, 'webaclId': '121c164d-aa19-4cb9-a089-a31432c9a997', 'terminatingRuleId': 'b40f89de-b044-418e-bb4a-064a0176e646', 'terminatingRuleType': 'REGULAR', 'action': 'BLOCK', 'httpSourceName': 'ALB', 'httpSourceId': '247130578221-app/awseb-AWSEB-FHA0YHXE8Z6W/570ea9ae9a194da6', 'ruleGroupList': [], 'rateBasedRuleList': [], 'nonTerminatingMatchingRules': [], 'httpRequest': {'clientIp': '49.255.65.166', 'country': 'AU', 'headers': [{'name': 'Host', 'value': 'backend-waf-test.us-east-1.elasticbeanstalk.com'}, {'name': 'User-Agent', 'value': 'curl/7.54.0'}, {'name': 'Accept', 'value': '*/*'}, {'name': 'x-i2g-correlation-id', 'value': '1234567890'}], 'uri': '/posts', 'args': 'q=helloio', 'httpVersion': 'HTTP/1.1', 'httpMethod': 'GET', 'requestId': None}}
print('this is the value', line_data)
print(line_data['httpRequest']['clientIp'])
print(line_data['httpRequest']['uri'])
print(line_data['httpRequest']['headers'])
```

# CorrelationID block solutions
```$xslt
create a sync worker
load data from S3
update list to memory
```


### DynamoDB Table
```$xslt
aws dynamodb create-table \
    --table-name abused_correlation_ids \
    --attribute-definitions \
        AttributeName=correlation_id,AttributeType=S AttributeName=updated_at,AttributeType=S \
    --key-schema AttributeName=correlation_id,KeyType=HASH AttributeName=updated_at,KeyType=RANGE \
    --provisioned-throughput ReadCapacityUnits=1,WriteCapacityUnits=1 \
    --region us-east-1
```


