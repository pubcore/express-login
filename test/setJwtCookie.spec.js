const createJwt = require('../js/lib/setJwtCookie'),
	{throws} = require('assert')

describe('creation of jwt cookie', () => {
	it('thows some exception to avoid invalid arguments', () => {
		throws(() => createJwt({}, {user:{}}, {}), TypeError)
		throws(() => createJwt({maxTimeWithout401: -1},{user:{}}, {}), TypeError)
		throws(() => createJwt({maxTimeWithout401: {}},{user:{}}, {}), TypeError)
	})
})