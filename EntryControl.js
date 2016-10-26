// EntryControl
// Michael Ramos
// v ?
// uuid: using rfc4122 v4 -- http://tools.ietf.org/html/rfc4122#page-14
'use strict';
import _    from 'lodash';
import uuid from 'node-uuid';
import jwt  from 'jsonwebtoken';

export function EntryControl(userOptions) {
    // base entry options (not user defined)
    this._options = {};
    try {
        this._validateUserOptions(userOptions);
        this._registerUserOptions(userOptions);
    } catch (e){
        console.log(e);
    }
}

// STUB
EntryControl.prototype._validateUserOptions = userOptions => {return true;};

EntryControl.prototype._registerUserOptions = userOptions => {
    let self = this;
    let protocols = userOptions.protocols || ["password"];
    
    let userOptions = {
      protocols:       protocols,
      protectedRoutes: userOptions.protectedRoutes || [],
      limitedRoutes:   userOptions.limitedRoutes   || [],
      databaseClient:  userOptions.databaseClient  || null,
      allowedIpRange:  userOptions.allowedIpRange  || null,
      tokenAlgorithm:  userOptions.tokenAlgorithm  || "HS256",
      logging:         userOptions.logging || false
    }
    
    if( protocols.indexOf("password") != -1 ) {
        userOptions.tokenType = 'jwt-password'
    } else {
        userOptions.tokenType = 'jwt-random'
    }
    
    self.config = Object.assign(userOptions, self._options);
    
    let _guardCommand = new GuardCommand(protocols, self.config);
    self._guardSquad = _guardCommand.squad;
}

EntryControl.prototype.gatewayVerification = request => {
    let self = this;
    let preVerify = false;
    
    if (request.cookies.ENTRY_CONTROL_TOKEN){
        preVerify = true;
    }
    
    let protect =  _.findIndex(self.config.protectedRoutes, r => {return (r.method == request.method && r.path == request.originalUrl);}) != -1;
    let limit   =  _.findIndex(self.config.limitedRoutes, r =>  {return (r.method == request.method && r.path   == request.originalUrl);}) != -1;
                     
    try {
        if (!preVerify && protect) {
            this._logger("Guard verifying new identity on protected route " + request.originalUrl );
            return this._guardSquad.verifyNewIdentity(request, 'protected');
        } else if(!preVerify && limit){
            this._logger("Guard verifying returning identity on limited route: " + request.originalUrl );
            return this._guardSquad.verifyNewIdentity(request, 'limited');
        } else if( preVerify && protect ) {
            this._logger("Guard verifying a retuning user for protected route: " + request.originalUrl );
            return this._guardSquad.verifyReturningIdentity(request, 'protected');
        } else if (preVerify && limit){
            this._logger("Guard verifying a retuning user for limited route: " + request.originalUrl );
            return this._guardSquad.verifyReturningIdentity(request, 'limited');
        } else {
            this._logger("Immediate bypass on unprotected route " + request.originalUrl );
            return {pass: true};
        }  
    } catch (e) {
        console.log(e);
    }
    
}

// STUB
EntryControl.prototype.gatewayInspection = request => {return true;}

EntryControl.prototype._logger = message => {
    if(this.config.logging == true) {
        console.log(new Date() + " 🚔  EntryControl :: " + message);
    }
}

function GuardCommand(protocols, config) {
    this.squad = this._createForce(protocols);
    this.config = config;
    this.signingSignature = uuid.v4();
    this.keyVault = {}; 
}

GuardCommand.prototype._createForce = protocols => {
    let self = this;
    let activateGuards = [];
    
    protocols.forEach((protocol,i) => {
         switch(protocol) {
            case "password":
                activateGuards.push(self._passwordGuard);
                break;
            case "ip":
                activateGuards.push(self._ipGuard);
                break;
            default:
                self._logger("problem creating guard for assignment type: " + type);
                break;
         }
    });
       
    return { 
        guardsOnDuty: activateGuards,
        verifyNewIdentity: (request, level) => {
            let decision = false;
            // bind self to the scopes
            if (request.isAuthenticated()) {
                self._logger("User is returning from a passport login.");
                decision = true;
            } else {
                self._logger("User not passport")
                self.squad.guardsOnDuty.forEach((guard,i) => {
                    decision = guard.verifyIdentity.call(self,request);
                }, self);
            }
            
            if(decision && level == 'protected') {
                return {pass: true, token: self._generateNewToken(request) };
            } else if( decision && level == 'limited' ) {
                return {pass: true, token: self._generateNewToken(request) };
            } else if ( level == 'limited' ){
                return {pass: true, noToken: true}
            } else {
                // passes did not check out
                return {pass: false };
            }
            
        }, 
        verifyReturningIdentity: (request, level) => {
            let decision = false;
            let decision = self._verifyGivenToken.call(self,request.cookies.ENTRY_CONTROL_TOKEN);
            if(decision) {
                // returning token valid
                return {pass: true, token: request.entryControlToken}
            } else {
                // token invalid, try for new one
                let that = self;
                return that.squad.verifyNewIdentity(request, level);
            }
        }
    };
}

// STUB
GuardCommand.prototype._passwordGuard = {
    verifyIdentity: (request) => {
        this._logger("implementing password guard verification");
        return true;
    },
    performInspection: (request) => {
        this._logger("implementing password guard verification");
        return true;
    }
}

GuardCommand.prototype._ipGuard = {
     verifyIdentity: (request) => {
        this._logger("implementing ip guard verification");
        let pass = this.config.allowedIpRange.indexOf(request.connection.remoteAddress) != -1;
        if (pass) {
            this._logger("ip identity verified");
        } else {
            this._logger("ip identity not verified")
        }
        return pass;
    },
    performInspection: (request) => {
        this._logger("implementing ip guard verification");
        return true;
    }
}

GuardCommand.prototype._verifyGivenToken = token => {
    let self = this;
    let isValid = false;
    try {
        let decoded = jwt.verify(token, self.signingSignature, { algorithm: self.tokenAlgorithm });
        isValid = self.keyVault[decoded.key] == decoded.value ? true : false;
    } catch(err) {
        this._logger("signing error or warning:")
        console.log(err)
    }
    if(isValid){
        this._logger("Returning User Validated");
    } else {
        this._logger("Returning User NOT validated");
    }
    return isValid;  
}

GuardCommand.prototype._generateNewToken = request => {
    let self = this;
    self._logger("generating a new token for verified user ");
    switch (self.config.tokenType) {
        case 'jwt-random':
            let unique_value = uuid.v4();
            let unique_key = uuid.v4();
            let expire = new Date();
            expire.setMinutes(expire.getMinutes() + 30);
            
            let token = jwt.sign({ 
                key: unique_key,
                value: unique_value,
                expire: expire
            }, self.signingSignature,
            { algorithm: self.tokenAlgorithm });
            
            self.keyVault[unique_key] = unique_value;
            return token;
        case 'jwt-password':
            // TODO create password checks 
            break;
        default:
            throw new Error("Cannont Generate New Token, no token type match");
    };
   
}

GuardCommand.prototype._logger = message => {
    if(this.config.logging == true) {
        console.log(new Date() + " 🚔  EntryControl ==> 👮  GuardCommand Logger :: " + message);
    }
}