'use strict'
const {deactivateUser, addLoginFailed, resetLoginFailedCount,
		updateLastLogin} = require('@pubcore/knex-auth'),
	http401 = require('../lib/http401').default,
	backCookie = require('../lib/createBackCookie').default

const redirectWithCookie = ({req, res, redirectUri}) => {
	res.setHeader('Set-Cookie',backCookie({uri: req.originalUrl}))
	req.path !== redirectUri && res.redirect(redirectUri)
}

exports.default = ({db, res, req, options}) => {
	var {publicDeactivatedUri, changePasswordUri, publicCancelLoginUri, methods} = options

	return {
		noCredentials: () => http401({publicCancelLoginUri, res, req, methods}),
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
		passwordExpired: () => redirectWithCookie({req, res, redirectUri: changePasswordUri}),
		loginExpired: () => redirectWithCookie({req, res, redirectUri: publicCancelLoginUri})
	}
}
