import {makeHandler} from 'fabo/packages/server-core/index.js'
import setupPassport from './services/passport.js'
import router from './.fabo/router.js'

const fabo_options = {
  whitelist: [
    'https://fabo-starter.vercel.app',
    'http://fabo-starter.vercel.app',
    'http://127.0.0.1:3000',
    'http://localhost:3000',
  ]
}

const startApp = makeHandler(router, [setupPassport], fabo_options)

export default startApp

