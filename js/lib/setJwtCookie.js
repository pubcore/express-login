'use strict'
const cookie = require('cookie'),
	JWT = require('jsonwebtoken'),
	getJwtDomain = require('./jwtDomain')

module.exports = ({jwtKey, jwtAlgorithm, maxTimeWithout401}, req, res) => {
	if(maxTimeWithout401 == undefined){
		throw new TypeError('Undefined config key: maxTimeWithout401')
	}
	var {user} = req,
		{username} = user,
		exp = Math.floor( (Date.now() + +maxTimeWithout401)/1000 )
	if(!Number.isInteger(exp) || +maxTimeWithout401 <= 0){
		throw new TypeError('Illegal config value for: maxTimeWithout401')
	}
	//set jwt cookie
	var Jwt = JWT.sign(
		{username, exp},
		jwtKey,
		{algorithm: jwtAlgorithm || 'HS256'}
	)
	res.setHeader(
		'Set-Cookie',
		cookie.serialize('Jwt', String(Jwt), {
			httpOnly: true,
			path: '/',
			secure: true,
			domain: getJwtDomain(req.get('host')),
			sameSite: 'lax'
		})
	)
}