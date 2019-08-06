'use strict'

exports.default = (users=[{}]) => users.map(usr => ({...{
	username:'eve',
	type:'HUMAN',
	deactivate:'no',
	login_failed_count:0,
	password:'$2y$04$RG9G38B8UD2zoHnP9MD2eunCc6hJxvmVly5r/1CRg9el3kfptw8Ra',
	last_login: new Date(),
	first_name: 'Ursa',
	last_name: 'Minor',
	email:'um@xy.com'
}, ...usr}))
