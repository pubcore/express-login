'use strict'

const cookie = require('cookie')

module.exports = ({uri}) => cookie.serialize(
	'back-uri',
	String(uri),
	{
		httpOnly: true,
		path:'/',
		secure:true
	}
)
