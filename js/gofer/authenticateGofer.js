'use strict'
const {deactivateUser, addLoginFailed, resetLoginFailedCount,
		updateLastLogin} = require('@pubcore/knex-auth'),
	http401 = require('../lib/http401').default,
	cookie = require('cookie')

exports.default = ({db, res, req, options}) => {
	var {publicDeactivatedUri, changePasswordUri, publicCancelLoginUri, methods} = options

	return {
		noCredentials: () => http401({publicCancelLoginUri, res, methods}),
		notFound: () => http401({publicCancelLoginUri, res, methods}),
		isDeactivated: () =>
			req.path !== publicDeactivatedUri && res.redirect(publicDeactivatedUri),
		toDeactivate: ({username}) => deactivateUser(db, {username}).then(
			() => res.redirect(publicDeactivatedUri)
		),
		invalidWebToken: () => http401({publicCancelLoginUri, res, methods}),
		invalidPassword: ({username}) => addLoginFailed(db, {username}).then(
			() => http401({publicCancelLoginUri, res, methods})
		),
		authenticated: (user, isTimeToUpdate) => {
			var {login_failed_count, username} = user
			return Promise.resolve(
				login_failed_count > 0 && resetLoginFailedCount(db, {username})
			).then(
				() => isTimeToUpdate && updateLastLogin(db, {username})
			).then(() => user)
		},
		oldPwUsed: user => (user.oldPwUsed = true) && user,
		passwordExpired: () => {
			res.setHeader(
				'Set-Cookie',
				cookie.serialize('back-uri', String(req.originalUrl), {
					httpOnly: true, path:'/', secure:true
				}))
			req.path !== changePasswordUri && res.redirect(changePasswordUri)
		}
	}
}
