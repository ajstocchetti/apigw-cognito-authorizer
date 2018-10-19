const params = require('./secrets.js');
for (secret in params) {
  process.env[secret] = params[secret];
}

const lambda = require('./lambda');

async function test() {
  const event = {
    authorizationToken: process.env.JWT,
    methodArn: 'arn:aws:execute-api:[region]:[account_id]:[restApiId]/[stage]/[method]/[resourcePath]',
    type: 'TOKEN',
  };
  const context = {};
  const policy = await lambda.handler(event, context);
  // console.log(require('util').inspect(policy, { depth: null }));
}


test();
