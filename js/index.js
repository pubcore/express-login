'use strict'
const knexAuth = require('@pubcore/knex-auth'),
	getUser = knexAuth.default,
	{comparePassword} = knexAuth,
	authenticate = require('@pubcore/authentication').default,
	gofer = require('./gofer/authenticateGofer'),
	setJwtCookie = require('./lib/setJwtCookie'),
	authOptions = require('./lib/authOptions')

exports.default = ({db, options}) => async (...args) => { try {
	var [req, res, next] = args,
		authOpts = await authOptions({req, options}),
		{methods, method, username, password, jwt, jwtList, jwtKey} = authOpts,
		user = await authenticate({
			carrier: {
				getOptions: () => Promise.resolve({...options, jwtKey}),
				getUser: ({username}) => getUser(
					{...db, cols:['first_name', 'last_name', 'email']}, {username}
				)
			},
			lib:{comparePassword},
			gofer: gofer({db, req, res, options:{...options, method}}),
			username, password, jwt, jwtList
		})

	if(user){
		let {username, email, first_name, last_name, last_login, oldPwUsed} = user
		req.user = {
			username, email, first_name, last_name, last_login, oldPwUsed
		}
		if(methods.jwt) setJwtCookie({...options, jwtKey}, req, res)
	}
	next()
}catch(e){next(e)}}
