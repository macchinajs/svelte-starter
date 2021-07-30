import {makeHandler} from 'fabo/packages/server-core'
import setupPassport from './services/passport.js'
import router from './.fabo/router.js'

const fabo_options = {
  whitelist: [
    'https://fabo-starter.vercel.app',
    'http://fabo-starter.vercel.app',
    'http://192.168.111.3:3000',
    'http://localhost:3000',
  ]
}

const startApp = makeHandler(router, [setupPassport], fabo_options)

export {startApp}

