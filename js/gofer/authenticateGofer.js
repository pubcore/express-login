'use strict'
const {deactivateUser, addLoginFailed, resetLoginFailedCount, updateLastLogin
	} = require('@pubcore/knex-auth'),
	reject = require('../lib/reject'),
	backCookie = require('../lib/createBackCookie'),
	url = require('url'),
	{normalize} = require('path'),
	pathEquals = (p1, p2) =>
		normalize(url.parse(p1).pathname + '/') === normalize(url.parse(p2).pathname + '/')

const redirectWithCookie = ({req, res, redirectUri}) => {
	res.setHeader('Set-Cookie', backCookie({uri: req.originalUrl}))
	res.redirect(redirectUri)
}

module.exports = ({db, res, req, options}) => {
	var {publicDeactivatedUri, changePasswordUri, publicCancelLoginUri, method} = options

	return {
		noCredentials: () => reject({publicCancelLoginUri, res, req, method, code:'NO_CREDS'}),
		notFound: () => reject({publicCancelLoginUri, res, method, code:'USER_NOT_FOUND'}),
		isDeactivated: () =>
			!pathEquals(req.path, publicDeactivatedUri) && res.redirect(publicDeactivatedUri),
		toDeactivate: async ({username}) => {
			await deactivateUser(db, {username})
			res.redirect(publicDeactivatedUri)
		},
		invalidWebToken: () => reject({publicCancelLoginUri, res, method, code:'INVALID_JWT'}),
		invalidPassword: async ({username}) => {
			await addLoginFailed(db, {username})
			reject({publicCancelLoginUri, res, method, code:'INVALID_PW'})
		},
		authenticated: async (user, isTimeToUpdate) => {
			var {login_failed_count, username} = user
			if(login_failed_count > 0) await resetLoginFailedCount(db, {username})
			if(isTimeToUpdate) await updateLastLogin(db, {username})
			return user
		},
		oldPwUsed: user => (user.oldPwUsed = true) && user,
		passwordExpired: (user) => {
			if(pathEquals(req.path, changePasswordUri)){
				return user
			}else{
				redirectWithCookie({req, res, redirectUri: changePasswordUri})
			}
		},
		loginExpired: async (user) => {
			if(pathEquals(req.path, publicCancelLoginUri)){
				var {username} = user
				await updateLastLogin(db, {username})
				return user
			}else{
				redirectWithCookie({req, res, redirectUri: publicCancelLoginUri})
			}
		}
	}
}
