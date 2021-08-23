import copy

SUBNET_KEYWORD = 'SubnetMappings'

#function process multi subnets, multi allowed port of network firewall template
def process_template(event):
    try:
        fragment = event['fragment']
        final_fragment = copy.deepcopy(fragment)
        parameters = event['templateParameterValues']
        subnet_ids = parameters['SubnetID'].split(',')
        subnet_results = []
        for subnet in subnet_ids:
            subnet_results.append({'SubnetId':subnet.strip()})
        resources = fragment['Resources']
        stateless_rules = parameters['StatelessRule'].split(',')
        stateless_results = []
        for rule in stateless_rules:
            stateless_results.append({'FromPort': rule.strip(),'ToPort': rule.strip()})
        for resource_name, resource_values in resources.items():
            #process for multi subnets
            if SUBNET_KEYWORD in resource_values['Properties']:
                final_fragment['Resources'][resource_name]['Properties'][SUBNET_KEYWORD] = subnet_results
            #process for multi allowed ports
            if resource_values['Type'] == 'AWS::NetworkFirewall::RuleGroup' and resource_values['Properties']['Type'] == 'STATELESS':
                final_fragment['Resources'][resource_name]['Properties']['RuleGroup']['RulesSource']['StatelessRulesAndCustomActions']['StatelessRules'][0]['RuleDefinition']['MatchAttributes']['DestinationPorts']=stateless_results
        return final_fragment
    except Exception as e:
        print("Error: " + str(e))
        
#function main to handle template event from cloudformation
def handle(event,context):
    print(event)
    processed_template=process_template(event)
    print(processed_template)
    r = {}
    r['requestId'] = event['requestId']
    r['status'] = 'SUCCESS'
    r['fragment'] = processed_template
    return r
