const elasticsearch = require('elasticsearch');
const connectionClass = require('http-aws-es');
const { v4: uuidV4 } = require('uuid');
const AWS = require('aws-sdk');
const FunctionShield = require('@puresec/function-shield');
const logger = require('pino')();

// Environment Variables
const ENV = process.env;
const es_endpoint = ENV.es_endpoint;
const region = ENV.region;
const roleArn = ENV.role_arn;
const snsArn = ENV.sns_arn;

AWS.config.update({
    credentials: new AWS.Credentials(
        process.env.AWS_ACCESS_KEY_ID,
        process.env.AWS_SECRET_ACCESS_KEY,
        process.env.AWS_SESSION_TOKEN
    ),
    region: region
});

const client = new elasticsearch.Client({
    host: es_endpoint,
    connectionClass: connectionClass,
    amazonES: {
        credentials: new AWS.EnvironmentCredentials('AWS')
    }
});

FunctionShield.configure(
    {
        policy: {
            read_write_tmp: 'alert',
            create_child_process: 'alert',
            outbound_connectivity: 'alert',
            read_handler: 'alert'
        },
        disable_analytics: false,
        token: ENV.function_shield_token
    });

exports.handler = async (input, context) => {
    context.callbackWaitsForEmptyEventLoop = false;

    const dataInput = JSON.parse(JSON.stringify(input));

    const taskArn = dataInput.detail.taskDefinitionArn;
    let nameTask = taskArn.split('/')[1].split('-')[0].split(':')[0];
    let idIndexPattern = '';

    const nameIndex = nameTask;
    // Check if exist index pattern
    try {
        const existIndexPattern = await client.search({
            _source: ['index-pattern.title'],
            body: {
                query: {
                    term: {
                        type: 'index-pattern'
                    }
                },
                size: 10000,
            }
        });


        const existIndex = existIndexPattern.hits.hits.find(item => {
            return item['_source']['index-pattern']['title'] === nameIndex;
        });

        if(!existIndex) {

            const bodyIndexPattern = {
                'type' : 'index-pattern',
                'index-pattern' : {
                    'title': nameIndex,
                    'timeFieldName': '@timestamp'
                }
            };

            idIndexPattern = uuidV4();
            const path = `/.kibana/doc/index-pattern:${idIndexPattern}`;

            const resCreateIndexPattern = await doRequest(
                bodyIndexPattern,
                path,
                'POST'
            );
        }else {
            idIndexPattern = existIndex._id.split(':')[1];
        }

    } catch (error) {
        logger.error('Error: ', error.message);
        return context.fail(error);
    }

    let destination = {};
    const existDest = await client.search({
        index: '.opendistro-alerting-config',
        body: {
            'query' : {
                'match' : {
                    'destination.type': 'sns'
                }
            }
        }
    });

    //Create destination if not exist
    if(existDest.hits.hits.length === 0) {
        const body = {
            'name': 'Triger-sns-lambda-slack',
            'type': 'sns',
            'sns':{
                'role_arn': roleArn,
                'topic_arn': snsArn,
            }
        };
        const destCreated = await doRequest(
            body,
            '/_opendistro/_alerting/destinations',
            'POST'
        );
        destination = JSON.parse(destCreated);
    }else {
        destination = existDest.hits.hits[0];
    }

    // Check if exists the monitor exist
    const existMonitor = await client.search({
        index: '.opendistro-alerting-config',
        body: {
            'query' : {
                'match' : {
                    'monitor.name': nameTask
                }
            }
        }
    });

    if(existMonitor.hits.hits.length === 0) {
        const account = await listAlias();

        // Create the monitor
        const dataMonitor = {
            'type' : 'monitor',
            'name' : nameTask,
            'enabled' : true,
            'schedule' : {
                'period' : {
                    'interval' : 1,
                    'unit' : 'MINUTES'
                }
            },
            'inputs' : [
                {
                    'search' : {
                        'indices' : [ nameIndex ],
                        'query' : {
                            'query' : {
                                'bool' : {
                                    'filter' : [
                                        {
                                            'term' : {
                                                'log' : {
                                                    'value' : 50,
                                                    'boost' : 1.0
                                                }
                                            }
                                        },
                                        {
                                            'range' : {
                                                '@timestamp' : {
                                                    'from' : '{{period_end}}||-1m',
                                                    'to' : '{{period_end}}',
                                                    'include_lower' : true,
                                                    'include_upper' : true,
                                                    'format' : 'epoch_millis',
                                                    'boost' : 1.0
                                                }
                                            }
                                        }
                                    ],
                                    'adjust_pure_negative' : true,
                                    'boost' : 1.0
                                }
                            }
                        }
                    }
                }
            ],
            'triggers' : [
                {
                    'name' : nameTask,
                    'severity' : '5',
                    'condition' : {
                        'script' : {
                            'source' : 'ctx.results[0].hits.total > 0',
                            'lang' : 'painless'
                        }
                    },
                    'actions' : [
                        {
                            'name' : `${nameTask.toUpperCase()} - errors`,
                            'destination_id' : destination._id,
                            'subject_template' : {
                                'source' : `${nameTask.toUpperCase()} messages error`,
                                'lang' : 'mustache'
                            },
                            'message_template' : {
                                'source' :
                                    `{{#ctx.results.0.hits.hits}}
    {
      "id": "{{_id}}",
      "nameService": "${nameTask}",
      "stage": "${account}",
      "log": "{{_source.log}}",
      "kibanaUrl": "https://${es_endpoint}/_plugin/kibana/app/kibana#/discover?_g=(refreshInterval:(pause:!t,value:0),time:(from:now-7d,mode:quick,to:now))&_a=(columns:!(_source),filters:!(('$state':(store:appState),meta:(alias:!n,disabled:!f,index:'${idIndexPattern}',key:'@id',negate:!f,params:(query:'{{_id}}',type:phrase),type:phrase,value:'{{_id}}'),query:(match:('@id':(query:'{{_id}}',type:phrase))))),index:'${idIndexPattern}',interval:auto,query:(language:lucene,query:''),sort:!('@timestamp',desc))"
    }
    SM_CUSTOM_DELIMITER
{{/ctx.results.0.hits.hits}}`,
                            }
                        }
                    ]
                }
            ]
        };
        try {
            let resCreatedMonitor = await doRequest(dataMonitor, '/_opendistro/_alerting/monitors', 'POST');
            resCreatedMonitor = JSON.parse(resCreatedMonitor);
        } catch (error) {
            logger.error(error);
            return context.fail(error);
        }
    }
    return context.succeed();
};

function doRequest(body, path, method) {
    return new Promise((resolve, reject) => {
        const endpoint = new AWS.Endpoint(es_endpoint);
        let request = new AWS.HttpRequest(endpoint, region);
        request.method = method;
        request.path = path;
        request.body = JSON.stringify(body);
        request.headers['host'] = es_endpoint;
        request.headers['Content-Type'] = 'application/json';

        const credentials = new AWS.EnvironmentCredentials('AWS');
        let signer = new AWS.Signers.V4(request, 'es');
        signer.addAuthorization(credentials, new Date());

        let client = new AWS.HttpClient();
        client.handleRequest(request, null, (response) => {
            let responseBody = '';
            response.on('data', (chunk) => {
                responseBody += chunk;
            });
            response.on('end', (chunk) => {
                resolve(responseBody);
            });
        }, (error) => {
            reject(error);
        });
    });
}

async function listAlias(){
    const iam = new AWS.IAM();
    const alias = await iam.listAccountAliases({}).promise();
    return alias.AccountAliases[0];
}
