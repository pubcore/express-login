'use strict'
const chai = require('chai'),
	{expect} = chai,
	login = require('../js/index').default,
	chaiHttp = require('chai-http'),
	express = require('express'),
	{dbTypes} = require('@pubcore/knex-auth'),
	createTestDb = require('@pubcore/knex-create-test-db'),
	defaultMap = require('./userDefaultMap').default,
	{resolve} = require('path'),
	cookie = require('cookie'),
	JWT = require('jsonwebtoken'),
	cookieParseSupportDuplicates = require('./cookieParseRepeated').parse

chai.use(chaiHttp)

const app = express(),
	app2 = express(), app3 = express(), app4 = express(), app5 = express(),
	app6 = express(), app7 = express(),
	options = {
		publicDeactivatedUri:'/login/deactivated',
		changePasswordUri:'/login/pwchange',
		publicCancelLoginUri:'/login/canceled',
		maxTimeWithoutActivity: 1000 * 60 * 60 * 24 * 180,//[msec],
		maxTimeWithout401: 1000 * 3600,//[msec]
		maxLoginAttempts:2,
		maxLoginAttemptsTimeWindow:50,//[msec]
		minTimeBetweenUpdates:1000,//[msec],
		jwtKeyFile:resolve(__dirname, 'jwtKey.txt')
	},
	table = 'user',
	knex = createTestDb({table, rows:defaultMap([{}, {
		username:'adam', password:null, last_login:null,
		password_new:'tempPw', created_time:new Date(),
		password_expiry_date:new Date()
	}, {
		username:'bob', last_login:new Date('2000-01-01T00:00:00')
	}, {
		username:'tom', password_secondary:'new'
	}, {
		username:'ben', password_expiry_date: new Date()
	}]), beforeEach, after, dbTypes:{
		...dbTypes, first_name:'string', last_name:'string', email:'string'
	}}),
	db = {knex, table},
	error = err => {throw err},
	Jwt = JWT.sign({ username: 'eve' }, 'somestring')

app.use(login({db, options}))
app.use('/', (req, res) => res.send(req.user))

//JWT support for app2
app2.use((req, res, next) => {
	req.cookies = cookie.parse(req.headers.cookie || '')
	req.cookiesByArray = cookieParseSupportDuplicates(req.headers.cookie || '', {parseToArray:true})
	next()
})
app2.use(express.json())
app2.use(express.urlencoded({ extended: true }))
app2.use(login({db, options}))
app2.use('/', (req, res) => res.send(req.user))

// post form login support for app3
app3.use(express.json())
app3.use(express.urlencoded({ extended: true }))
app3.use(login({db, options}))
app3.use('/', (req, res) => res.send(req.user))

// deactivated basic authentication
app4.use(login({db, options:{...options, methods: {jwt:{},form:{}}}}))
app4.use('/', (req, res) => res.send(req.user))

// invalid key file
app5.use(login({db, options:{...options, jwtKeyFile:resolve(__dirname, 'jwtKey_not_found.txt'), methods: {jwt:{},form:{}}}}))
app5.use('/', (req, res) => res.send(req.user))

//JWT support for app6, but with very short login expiry time
app6.use(express.urlencoded({ extended: true }))
app6.use((req, res, next) => {
	req.cookies = cookie.parse(req.headers.cookie || '')
	next()
})
app6.use(login({db, options:{...options, maxTimeWithout401: 50, jwtKeyFile:resolve(__dirname, 'jwtKey.txt')}}))
app6.use('/', (req, res) => res.send(req.user))

app7.use((req, res, next) => {
	req.cookies = cookie.parse(req.headers.cookie || '')
	next()
})
app7.use(login({db, options:{...options, methods: {basicAuth:{}}}}))
app7.use('/', (req, res) => res.send(req.user))

var lastMediaType = 0
const aMediaType = () => {
	return (['text/html', 'application/json', 'application/xml'])[++lastMediaType%3]
}
const repead = (n, p) => {
	return Promise.all((new Array(n)).map(() => p))
}
const expectReject = (status=200) => res => {
	expect(res).to.have.status(status)
	expect(res.text).to.contain(options.publicCancelLoginUri)
}
const expect200 = res => {
	expect(res).to.have.status(200)
	expect(res.text).to.contain('um@xy.com')
}
const wait = ms => new Promise(res => setTimeout(()=>res(), ms))
const wrongBasicAuthRequest = () =>
	chai.request(app).get('/').set('Accept', aMediaType()).redirects(0).auth('eve', 'xyz')
const correctBasicAuthRequest = (username='eve') =>
	chai.request(app).get('/').redirects(0).auth(username, 'test')

describe('http authentication service based on @pubcore/authentication flow', () => {
	it('exports API', () => expect(login).not.to.be.undefined)
	it('serves allways reject containing cancel URI, if no credentials',() =>
		repead(3, chai.request(app).get('/').redirects(0).then(expectReject()))
	)
	it('rejects, if user not found',() =>
		chai.request(app).get('/').redirects(0).auth('xyz', 'test').then(expectReject(401))
	)
	it('serves "200 ok" and user data, if username and password is ok',() =>
		correctBasicAuthRequest().then(expect200, error)
	)
	it('redirect to "deactivated" page, if wrong password used too much within a time window',() =>
		wrongBasicAuthRequest().then(expectReject(401))
		//after a correct request counter is reset
			.then(() => correctBasicAuthRequest().then(expect200))
			.then(() => wrongBasicAuthRequest().then(expectReject(401)))
		//wait to get outsite of time window
			.then(() => wait(options.maxLoginAttemptsTimeWindow))
			.then(() => wrongBasicAuthRequest().then(expectReject(401)))
			.then(() => wrongBasicAuthRequest().then(
				res => expect(res).redirectTo(options.publicDeactivatedUri)
			))
		//now, even a request with correct password must lead to deactivated
			.then(() => correctBasicAuthRequest().then(
				res => expect(res).redirectTo(options.publicDeactivatedUri)
			))
	)
	it('redirect to "deactivated" page, if last login of user is long time ago', () =>
		chai.request(app).get('/').redirects(0).auth('bob', 'test')
			.then(res => expect(res).redirectTo(options.publicDeactivatedUri))
	)
	it('updates last login stamp, one time within defined time frame', () => {
		var firstStamp
		return correctBasicAuthRequest().then(({body}) => {
			firstStamp = body.last_login
		}, error)
			.then(() => correctBasicAuthRequest().then(({body}) => {
				expect(firstStamp).to.equal(body.last_login)
			}, error))
			.then(() => wait(options.minTimeBetweenUpdates))
			.then(() => correctBasicAuthRequest())
			.then(() => correctBasicAuthRequest().then(({body}) => {
				expect(firstStamp).to.not.equal(body.last_login)
			}, error))
	})
	it('redirects to change password page (including a back-uri), on first request of new user', () => {
		var uri = '/xyz/?foo=bar'
		return chai.request(app).get(uri).redirects(0).auth('adam', 'tempPw').then(
			res => expect(res)
				.redirectTo(options.changePasswordUri)
				.and.to.have.cookie('back-uri', encodeURIComponent(uri))
		)
	})
	it('redirects to change password page (including a back-uri), if password is expired', () => {
		var uri = '/foo/?bar=xyz'
		return chai.request(app).get(uri).redirects(0).auth('ben', 'test').then(
			res => expect(res)
				.redirectTo(options.changePasswordUri)
				.and.to.have.cookie('back-uri', encodeURIComponent(uri))
		)
	})
	it('does not redirect, if redirect-target URI is requested (avoid redirect loops)', () =>
		chai.request(app).get(options.changePasswordUri).redirects(0).auth('ben', 'test').then(
			res => expect(res).to.have.status(200)
		)
	)
	it('does set a flag (oldPwUsed), if secondary password exists, but old password has been used', () =>
		correctBasicAuthRequest('tom').then(({body}) => expect(body.oldPwUsed).to.be.true)
	)
	it('does not add password fields to user object', () =>
		correctBasicAuthRequest('tom').then(({body}) =>
			expect(JSON.stringify(body)).to.not.contain('password')
		)
	)
	it('serves basic user data', () =>
		correctBasicAuthRequest('tom').then(({body}) =>
			expect(JSON.stringify(body)).to.contain('first_name')
				.and.contain('last_name').and.contain('email')
		)
	)
	it('should fail, because of deactivated method', () => chai.request(app4).get('/').redirects(0).auth('eve', 'test').then(expectReject()))
	it('force reject/login based on configured maxTimeWithout401 (session expiry)', () =>
		chai.request(app6).get('/').set('Cookie', cookie.serialize('Jwt', Jwt))
			.redirects(0).then(
				res => expect(res).redirectTo(options.publicCancelLoginUri)
					.and.to.have.cookie('back-uri', encodeURIComponent('/'))
			)
	)
	it('expired login is updated, if login-request\'s URI equals "publicCancelLoginUri"', () =>
		chai.request(app6).post(options.publicCancelLoginUri).type('form').send({username: 'eve', password: 'test'}).then(
			res => {
				expect(res).to.have.status(200)
				expect(res.text).to.not.contain(options.publicCancelLoginUri)
				expect(res.text).to.contain('last_name').and.contain('um@xy.com')
			}
		)
	)
	describe('Json Web Token (JWT) based login', () => {
		it('rejects if jwt key file cannot be loaded', () =>
			chai.request(app5).get('/').set('Cookie', cookie.serialize('Jwt', Jwt)).redirects(0).then(
				res => expect(res).to.have.status(500), error
			)
		)
		it('supports (optional) login by Json Web Token (JWT); depends on jwtKeyFile option exists (staticly cached)', () =>
			chai.request(app2).get('/').set('Cookie', cookie.serialize('Jwt', Jwt)).redirects(0).then(
				expect200, error
			)
		)
		it('should set a valid JWT cookie after valid login', () =>
			chai.request(app2).post('/').type('form').send({username: 'eve', password: 'test'}).then(
				res => expect(res).to.have.cookie('Jwt'), error
			)
		)
		it('support login, if two JWT cookies given with same name', async () => {
			await chai.request(app2).get('/').set('Cookie', `Jwt=foo; Jwt=${Jwt}`).redirects(0).then(
				expect200, error
			)
			await chai.request(app2).get('/').set('Cookie', `Jwt=${Jwt}; Jwt=foo`).redirects(0).then(
				expect200, error
			)
		})
		it('rejects, if JWT is invalid', () =>
			chai.request(app2).get('/').set('Cookie', cookie.serialize('Jwt', Jwt+'garbleIt')).redirects(0).then(
				expectReject(), error
			)
		)
		it('should set/update JWT cookie, if valid credentials are given', () =>
			chai.request(app2).post('/')
				.set('Cookie', cookie.serialize('Jwt', 'invalidJwt'))
				.send({username: 'eve', password: 'test'}).redirects(0).then(
					res => {
						expect(res).to.have.cookie('Jwt')
						expect(res).to.have.status(200)
						expect(res.text).to.not.contain(options.publicCancelLoginUri)
					}, error
				)
		)
		it('rejects, if jwt is disabled but valid token is there', () =>
			chai.request(app7).get('/')
				.set('Cookie', cookie.serialize('Jwt', Jwt)).redirects(0).then(
					expectReject(), error
				)
		)
		it('must login, if jwt is disabled, creds are valid and JWT is invalid', () =>
			chai.request(app7).get('/').auth('eve', 'test')
				.set('Cookie', cookie.serialize('Jwt', 'invalid')).redirects(0).then(
					expect200, error
				)
		)
	})
	describe('Form based login', () => {
		it('rejects, if no creds given', () =>
			chai.request(app3).post('/').type('form').send().then(expectReject()))
		it('rejects, on wrong creds', () =>
			chai.request(app3).post('/').type('form').send({username: 'test', password: 'test'}).then(expectReject()))
		it('responds with http 200 and req objects contains some user data', () =>
			chai.request(app3).post('/').type('form').send({username: 'eve', password: 'test'}).then(expect200))
		it('must not response with 401, if post data is send and invalid', () =>
			chai.request(app3).post('/').type('form').send({username: 'test', password: 'test'}).then(
				res => {
					expect(res).not.to.have.header('WWW-Authenticate')
					expect(res).to.not.have.status(401)
				}
			)
		)
	})
})
