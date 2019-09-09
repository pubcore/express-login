'use strict'

const cookie = require('cookie')

exports.default = ({uri}) => cookie.serialize(
	'back-uri',
	String(uri),
	{
		httpOnly: true,
		path:'/',
		secure:true
	}
)
