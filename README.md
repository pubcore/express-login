## Express authentication middleware
Implementation for [@pubcore/authentication](https://github.com/pubcore/authentication)

#### Prerequisites
* Node.js
* Express webserver
* Knex

#### Example
```
const login = require('@pubcore/express-login'),
	app = express(),
	options = {
		methods: {jwt:{}, form:{}, basicAuth:{}},
		publicDeactivatedUri: '/login/deactivated',
		publicCancelLoginUri: '/login/canceled',
		changePasswordUri:'/login/pwchange',
		maxTimeWithoutActivity: 1000 * 60 * 60 * 24 * 180, //[msec]
		maxTimeWithout401: 1000 * 3600, //[msec]
		maxLoginAttempts: 2,
		maxLoginAttemptsTimeWindow: 1000 * 3600 * 12, //[msec]
		minTimeBetweenUpdates: 1000 * 60, //[msec]
		jwtKeyFile: '/path/to/keyfile'
	},
	db = {knex, table:'users'}

app.use(login({db, options}))
```
