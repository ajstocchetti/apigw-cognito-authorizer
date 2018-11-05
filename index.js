const jwt = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const rp = require('request-promise');
const AuthPolicy = require('./auth-policy');

// see http://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html
// ispired by reference app at https://github.com/awslabs/aws-serverless-auth-reference-app/blob/master/api/lambda/authorizer.js

class Authorizer {
  constructor({
    userPoolId,
    region,
    parseToken,
  }) {
    if (typeof parseToken === 'function') this.parseToken = parseToken;
    else this.parseToken = function(authToken) { return authToken; };

    this.userPoolURI = `https://cognito-idp.${region}.amazonaws.com/${userPoolId}`;
    const jwtKeySetURI = `${this.userPoolURI}/.well-known/jwks.json`;

    this._allPems = null;
    this.getPems = async function getPems() {
      if (!this._allPems) {
        const keySet = await rp({ url: jwtKeySetURI, json: true });
        this._allPems = pivotKeysToKid(keySet.keys);
      }
      return this._allPems;
    }
  }

  async processEvent(event) {
    try {
      const token = await this.parseEventToken(event);
      return allAccessPolicy(token.sub, event);
    } catch(error) {
      console.warn(error.message);
      return noAccessPolicy(event);
    }
  }

  async parseEventToken(event) {
    const token = this.parseToken(event.authorizationToken);
    // Fail if there is no token
    if (!token) {
      throw new Error('No token provided');
    }

    const decodedJwt = jwt.decode(token, { complete: true });
    //Fail if the token is not jwt
    if (!decodedJwt) {
      throw new Error(`Missing or invalid JWT: ${token}`);
    }

    const issuer = this.userPoolURI;
    //Fail if token is not from our User Pool
    if (decodedJwt.payload.iss != issuer) {
      throw new Error(`Provided Token not from correct UserPool: iss = ${decodedJwt.payload.iss}`);
    }

    //Reject the jwt if it's not an 'Identity Token'
    if (decodedJwt.payload.token_use != 'id') {
      throw new Error(`Provided Token is not an identity token: ${decodedJwt.payload.token_use}`);
    }

    const allPems = await this.getPems();
    const pem = allPems[decodedJwt.header.kid];
    // Reject if JWK is not valid
    if (!pem) {
      throw new Error('Invalid JSON Web Key');
    }

    // jwt.verify will throw an error if the token is invalid
    return jwt.verify(token, pem, { issuer });
  }
}


function pivotKeysToKid(keys) {
  return keys.reduce((allPems, key) => {
    allPems[key.kid] = jwkToPem(key);
    return allPems;
  }, {});
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
