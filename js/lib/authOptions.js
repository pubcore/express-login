'use strict'
const getCreds = require('basic-auth'),
	{readFile} = require('fs'),
	loadSecret = file => new Promise((resolve, reject) => readFile(
		file,
		{encoding:'utf8'},
		(err, data) => err ? reject(err) : resolve(data.trim())
	))

module.exports = async ({req, options}) => {
	var {jwtKeyFile} = options,
		methods = options.methods || {jwt:{}, basicAuth:{}, form:{}},
		{basicAuth, form, jwt} = methods,
		jwtKey = jwt && await loadSecret(jwtKeyFile),
		{body, cookiesByArray, cookies} = req,
		{Jwt} = cookies || {},
		method = jwt ? 'jwt' : '',
		jwtList = (cookiesByArray||{})['Jwt']

	if(basicAuth) {
		var {name, pass} = getCreds(req) || {}
		if(name || pass){
			method = 'basicAuth'
		}
	}
	
	if(form && req.method === 'POST' && body && (body.username || body.password)){
		name = body.username,
		pass = body.password,
		method = 'form'
	}
	return ({
		method, methods, username: name, password: pass, jwtKey,
		...(method=='jwt' ? {jwt: Jwt, jwtList} : {})
	})
}