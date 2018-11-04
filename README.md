# AWS Api Gateway Cognito Custom Authenticator

This library is a tool to make it easier to build custom authorizers for AWS Api Gateway that are authenticating JWTs from Amazon Cogntio User Pools. Rather than copy the same boilerplate code for all of your apps, require this one library, instantiate it with your Cogntio User Pool id, to and you're good to go.


Currently, this only serves as an authenticator (and not an authorizer). You will need to authorize access in your applications. There are plans to enhance this library to provide authorization as well. It will require a function that takes an unpacked JWT and returns a list of allowed routes/methods, or alternatively takes the JWT and the route and returns true/false if the user has access.


## Usage
### Install

```bash
npm install apigateway-cognito-authorizer
```

### Instantiate

```javascript
const cognitoAuthorizer = require('apigateway-cognito-authorizer');

// instantiate new authorizer outside of handler function
// so that the JWT Pems can be cached between lambda invocations
const auth = new cognitoAuthorizer({
  userPoolId: `user_pool_id`,
  region: `us-east-1`, // or wherever your code lives...
  parseToken: function(auth) {
    return auth.split('Bearer ')[1]; // Bearer token syntax
  },
});

exports.handler = async(event, context) => await auth.processEvent(event);
```

## Api
**instantiate new authorizer**

```javascript
const auth = new cognitoAuthorizer({
  userPoolId: `user pool id`,
  region: `us-east-1`,
  parseToken: parseFunction,
});
```
Parameter: Options object with the following keys
- userPoolId: the Amazon Cognito User Pool Id
- region: the AWS region this APIGateway/Authorizer is running in
- parseToken: optional - a function that takes the auth token (from the `authorizationToken` key on the lambda `event`) and returns the JWT. This is useful if the JWT is passed in as a bearer token and the "Bearer " needs to be stripped off. If no function is supplied, the full `event.authorizationToken` will be used as the JWT.

The instantiation of a new Authorizer triggers the downloading of JWKs from AWS. These JWKs are cached in memory to speed up the processing of any individual invocation of this lambda function. For this reason, it is encouraged to instantiate the Authorizer outside of the lambda handler so that the JWKs are cached between lambda invocations (provided the same container is used).

**processEvent**

```javascript
auth.processEvent(event);
```
Parameters: event - the lambda event
Returns a promise that resolves an IAM policy for the API Gateway


## Next steps
0. Add authorization (see above)
0. replace rp with regular request and promisify it here to reduce size of dependencies
