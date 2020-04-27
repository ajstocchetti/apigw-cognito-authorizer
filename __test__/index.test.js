const cognitoAuthorizer = require('../index');
const cognitoJwtAuth = require('aws-cognito-jwt-authenticate');

const testRegion = '[region]';
const testPoolId = 'some-pool';
const testJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdWJqZWN0IiwiYXVkIjoiYXVkaWVuY2UiLCJpc3MiOiJzb21lLXVzZXItcG9vbC1zdHJpbmciLCJ0b2tlbl91c2UiOiJpZCIsImNvZ25pdG86dXNlcm5hbWUiOiJ0ZXN0In0.bQxbXSoZHpl4VauVPMu2l_F0mCypckEW4Y3G9Ogeb5g';
const testPayload = {
  "sub": "subject",
  "aud": "audience",
  "iss": "some-user-pool-string",
  "token_use": "id",
  "cognito:username": "test"
};
const event = {
  authorizationToken: testJwt,
  methodArn: 'arn:aws:execute-api:[region]:[account_id]:[restApiId]/[stage]/[method]/[resourcePath]',
  type: 'TOKEN',
};


describe('Authorizer class', () => {

  describe('On successful JWT', () => {
    beforeAll(() => {
      cognitoJwtAuth.validateJwt = jest.fn(async () => (testPayload));
    });

    afterAll(() => {
      cognitoJwtAuth.validateJwt.mockRestore();
    });


    test('Provides full access policy', async () => {
      const auth = new cognitoAuthorizer({
        userPoolId: testPoolId,
        region: testRegion,
      });
      const policy = await auth.processEvent(event);
      // console.log(require('util').inspect(policy, { depth: null }));

      expect(policy.principalId).toEqual('subject');
      expect(policy).toHaveProperty('policyDocument');
      expect(policy.policyDocument).toHaveProperty('Statement');
      expect(Array.isArray(policy.policyDocument.Statement)).toBe(true);
      const statement = policy.policyDocument.Statement[0];
      expect(statement.Effect).toEqual('Allow');
      expect(statement.Action).toEqual('execute-api:Invoke');
      expect(statement.Resource).toContain(
        'arn:aws:execute-api:[region]:[account_id]:[restApiId]/[stage]/*/*'
      );
    });
  });

  describe('On invalid JWT', () => {
    beforeAll(() => {
      cognitoJwtAuth.validateJwt = jest.fn(async () => { throw new Error('I dont like your JWT'); });
    });

    afterAll(() => {
      cognitoJwtAuth.validateJwt.mockRestore();
    });


    test('Provides no access policy', async () => {
      const auth = new cognitoAuthorizer({
        userPoolId: testPoolId,
        region: testRegion,
        echoFail: false,
      });
      const policy = await auth.processEvent(event);

      expect(policy).toHaveProperty('policyDocument');
      expect(policy.policyDocument).toHaveProperty('Statement');
      expect(Array.isArray(policy.policyDocument.Statement)).toBe(true);
      expect(policy.policyDocument.Statement[0].Effect).toEqual('Deny');
    });
  });
});