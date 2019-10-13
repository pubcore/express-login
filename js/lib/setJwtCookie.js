'use strict'
const cookie = require('cookie'),
	JWT = require('jsonwebtoken'),
	getJwtDomain = require('./jwtDomain')

module.exports = ({jwtKey, jwtAlgorithm, maxTimeWithout401}, req, res) => {
	var {user} = req,
		{username} = user,
		exp = Math.floor((new Date() + +maxTimeWithout401) / 1000)
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