import {ok} from 'assert'
import main from '../src/index'

describe('my module', ()=>{
	it('exports an object', () =>{
		ok(typeof main === 'object')
	})
})