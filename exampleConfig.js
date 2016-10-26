import EntryControl from './EntryControl';

// setup
// EntryControl Config
let EC = new EntryControl({
  // type of protocol: ip, user/pass (not implemented)
  protocols: ["ip"],
  allowedIpRange: ['<insert range here>, <or a list>'],
  // fully protected routes
  protectedRoutes: [
    {path: '/path/one',  method: 'POST'}, 
    {path: '/path/two',  method: 'PUT'}, 
    {path: '/singroute', method: 'GET'}, 
    {path: '/*',         method: '*'} 
  ],
  // gives a token on entry (if applicable)
  limitedRoutes: [
    {path: '/' , method: 'GET'}  
  ],
  logging: app.get('env') == 'production' ? false : true
});

// implementation
// hook in IP/Token Protection - EntryControl
app.use( (req, res, next) => {
  var verdict = EC.gatewayVerification(req); // returns pass message and token
  if(verdict.pass === true && verdict.token) {
    res.cookie("ENTRY_CONTROL_TOKEN" , verdict.token);
    next();
  } else if (verdict.pass) {
    next();
  } else  {
    res.status(401).send("Access Denied for unauthorized user");
  }
});