import {makeHandler} from '@macchina/server-core'
import setupPassport from './services/passport.js'
import router from './.macchina/router.js'

const macchina_options = {
  whitelist: [
    'https://macchina-starter.vercel.app',
    'http://macchina-starter.vercel.app',
    'http://127.0.0.1:3000',
    'http://localhost:3000',
  ]
}

const startApp = makeHandler(router, [setupPassport], macchina_options)

export default startApp

