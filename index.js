const auth = require('aws-cognito-jwt-authenticate');
const AuthPolicy = require('./auth-policy');

// see http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
// ispired by reference app at https://github.com/awslabs/aws-serverless-auth-reference-app/blob/master/api/lambda/authorizer.js

class Authorizer {
  constructor({
    userPoolId,
    region,
    parseToken,
    echoFail = true,
  }) {
    if (typeof parseToken === 'function') this.parseToken = parseToken;
    else this.parseToken = function(authToken) { return authToken; };

    this.cognitoDetails = { userPoolId, region };

    this._echoFail = !!echoFail;
  }

  async processEvent(event) {
    try {
      const token = this.parseToken(event.authorizationToken);
      const payload = await auth.validateJwt(token, this.cognitoDetails);
      return allAccessPolicy(payload.sub, event);
    } catch(error) {
      if (this._echoFail) console.warn(error.message);
      return noAccessPolicy(event);
    }
  }
}


function unpackEvent(event) {
  const tmp = event.methodArn.split(':');
  const apiGatewayArnTmp = tmp[5].split('/');
  const awsAccountId = tmp[4];
  const apiOptions = {
    region: tmp[3],
    restApiId: apiGatewayArnTmp[0],
    stage: apiGatewayArnTmp[1],
  };
  return { apiOptions, awsAccountId };
}

function allAccessPolicy(principal, event) {
  const { apiOptions, awsAccountId } = unpackEvent(event);
  const policy = new AuthPolicy(principal, awsAccountId, apiOptions);
  policy.allowAllMethods();
  return policy.build();
}

function noAccessPolicy(event) {
  const { apiOptions, awsAccountId } = unpackEvent(event);
  const policy = new AuthPolicy('', awsAccountId, apiOptions);
  policy.denyAllMethods();
  return policy.build();
}

module.exports = Authorizer;