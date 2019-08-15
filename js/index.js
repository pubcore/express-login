'use strict'
const basicAuth = require('basic-auth'),
	knexAuth = require('@pubcore/knex-auth'),
	getUser = knexAuth.default,
	{comparePassword} = knexAuth,
	authenticate = require('@pubcore/authentication').default,
	gofer = require('./gofer/authenticateGofer').default,
	{readFile} = require('fs'),
	cookie = require('cookie'),
	JWT = require('jsonwebtoken'),
	authenticateOptions = { //all time values in [ms]
		maxTimeWithoutActivity: 1000 * 60 * 60 * 24 * 180,
		maxLoginAttempts:5,
		maxLoginAttemptsTimeWindow:1000 * 60 * 60 * 24,
	},
	httpOptions = {
		changePasswordUri:'/login/pwChange',
		publicDeactivatedUri:'/login/deactivated',
		publicCancelLoginUri:'/login/canceled',
	},
	loadSecret = file => new Promise((resolve, reject) => readFile(
		file,
		{encoding:'utf8'},
		(err, data) => err ? reject(err) : resolve(data.trim())
	))

var jwtKey = ''

exports.default = ({db, options}) => (...args) => {
	var [req, res, next] = args,
    authMethods = options.methods || {jwt:{}, basicAuth:{}, form:{}},
		{body, cookies, cookiesByArray} = req,
		{Jwt} = cookies || {},
    authOptions = {
  		carrier: {
  			getOptions: () => Promise.resolve(
  				options.jwtKeyFile && !jwtKey && loadSecret(options.jwtKeyFile)
  					.then(data => jwtKey = data, err => Promise.reject(err))
  			).then(() => ({...authenticateOptions, ...options, jwtKey})),
  			getUser:({username}) => getUser(
  				{...db, cols:['first_name', 'last_name', 'email']}, {username}
  			)
  		},
  		lib:{comparePassword}
  	}

    if(authMethods.jwt) {
      authOptions.jwt = Jwt
      authOptions.jwtList = (cookiesByArray||{})['Jwt']
    }

    if(authMethods.basicAuth) {
      var basicAuthData = basicAuth(req)
      if(basicAuthData) {
        authOptions.username = basicAuthData.name
        authOptions.password = basicAuthData.pass
      }
    }

    if(authMethods.form && !authOptions.username && !authOptions.password) {
      if(body && body.username && body.password) {
        authOptions.username = body.username
        authOptions.password = body.password
				delete authMethods.basicAuth
      }
    }

		authOptions.gofer = gofer({
			db, req, res, options:{...httpOptions, ...options, methods: authMethods}
		})

	return authenticate(authOptions).then(user => {
		Promise.resolve(
			options.jwtKeyFile && !jwtKey && loadSecret(options.jwtKeyFile)
				.then(data => jwtKey = data, err => Promise.reject(err))
		).then(() => {
			if(user){
				var {username, email, first_name, last_name, last_login, oldPwUsed} = user
				//set jwt cookie
				if(authMethods.jwt && jwtKey && typeof(Jwt) === 'undefined') {
					Jwt = JWT.sign({ username, exp: Math.floor(new Date() / 1000) + (360 * 60) }, jwtKey, { algorithm: options.algorithm || 'HS256'})
					res.setHeader(
						'Set-Cookie',
						cookie.serialize('Jwt', String(Jwt), {
							httpOnly: false, maxAge: 0, path:'/', secure:true
						}))
				}
				req.user = {
					username, email, first_name, last_name, last_login, oldPwUsed
				}
			}
			next()
		})

	}).catch(next)
}
