const cognitoAuthorizer = require('../index');

const auth = new cognitoAuthorizer({
  userPoolId: process.env.USER_POOL_ID,
  region: process.env.REGION,
});

exports.handler = async(event, context) => await auth.processEvent(event);
