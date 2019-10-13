'use strict'

module.exports = host => {
	var dp = host.split('.'),
		n = dp.length,
		domain = dp[n-2] + '.' + dp[n-1]
	if(n > 3){
		domain = dp[n-3] + '.' + domain
	}
	return domain
}