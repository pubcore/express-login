'use strict'

const backCookie = require('../lib/createBackCookie').default

exports.default = ({publicCancelLoginUri, res, req, methods}) => {
	var text = 'Unauthorized (401)'
	res.status(401)
	if(methods.basicAuth) {
		res.append(
			'WWW-Authenticate',
			'Basic Realm="Pls cancel this dialog if you forgot your password."'
		)
	}
	if(req) {
		res.setHeader('Set-Cookie',backCookie({uri: req.originalUrl}))
	}
	res.format({
		'text/html': () => res.send(`<!DOCTYPE html>
<html><body>
	${text}
	<script>document.location.href='${publicCancelLoginUri}'</script>
</body></html>`
		),
		'application/json': () =>
			res.send({status:{code:'ERROR', text}, publicCancelLoginUri}),
		default: () => res.send(text + '; see ' + publicCancelLoginUri)
	})
}
