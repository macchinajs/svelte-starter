import {makeHandler} from 'fabo/packages/server-core'
import setupPassport from './services/passport.js'
import router from './.fabo/router.js'

const startApp = makeHandler(router, [setupPassport])

export {startApp}
