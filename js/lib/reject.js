'use strict'

const backCookie = require('../lib/createBackCookie')

module.exports = ({publicCancelLoginUri, res, req, method, code}) => {
	var text = 'Unauthorized'
	if(method === 'basicAuth') {
		res.status(401)
		res.append(
			'WWW-Authenticate',
			'Basic Realm="Pls cancel this dialog if you forgot your password."'
		)
	}else{
		res.status(200)
	}

	if(req) {
		res.setHeader('Set-Cookie', backCookie({uri: req.originalUrl}))
	}
	res.format({
		'text/html': () => res.send(`<!DOCTYPE html>
<html><body>
	${text} (${code})
	<script>document.location.href='${publicCancelLoginUri}'</script>
</body></html>`
		),
		'application/json': () =>
			res.send({status:{code, text}, publicCancelLoginUri}),
		default: () => res.send(text + '; see ' + publicCancelLoginUri)
	})
}
