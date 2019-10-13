'use strict'
const jwtDoamin = require('../js/lib/jwtDomain')
const {equal} =  require('assert')

describe('support cross domain JWT cookies', () => {
	it('omits subdomain of given domain', () => {
		equal(jwtDoamin('sub.of.some.domain'), 'of.some.domain')
		equal(jwtDoamin('sub.of.other'), 'of.other')
	})
})