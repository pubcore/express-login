'use strict'

//TODO workarround unless https://github.com/jshttp/cookie/pull/85 is not merged ...

const decode = decodeURIComponent,
	pairSplitRegExp = /; */,
	tryDecode = (str, decode) => {
		try {
			return decode(str)
		} catch (e) {
			return str
		}
	}

module.exports = {parse:(str, options) => {
	if (typeof str !== 'string') {
		throw new TypeError('argument str must be a string')
	}

	var obj = {}
	var opt = options || {}
	var pairs = str.split(pairSplitRegExp)
	var dec = opt.decode || decode
	var toArray = opt.parseToArray

	for (var i = 0; i < pairs.length; i++) {
		var pair = pairs[i]
		var eq_idx = pair.indexOf('=')

		// skip things that don't look like key=value
		if (eq_idx < 0) {
			continue
		}

		var key = pair.substr(0, eq_idx).trim()
		var val = pair.substr(++eq_idx, pair.length).trim()

		// quoted values
		if ('"' == val[0]) {
			val = val.slice(1, -1)
		}

		// assign initial value
		if (undefined == obj[key]) {
			obj[key] = toArray ? [tryDecode(val, dec)] : tryDecode(val, dec)
		} else if(toArray){
			// concat to previous value(s)
			obj[key] = obj[key].concat(tryDecode(val, dec))
		}
	}

	return obj
}}
