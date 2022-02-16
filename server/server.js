import startApp from './handler.js'
import mongoose from 'mongoose'

const app = await startApp(mongoose, true)
