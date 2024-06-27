import { Router } from 'express'
import {
  accessTokenValidator,
  emailVerifyTokenValidator,
  loginValidator,
  refreshTokenValidator,
  registerValidator
} from '../middlewares/users.middlewares.js'
import {
  emailVerifyTokenController,
  loginController,
  logoutController,
  registerController
} from '../controllers/users.controllers.js'
import { wrapAsync } from '../utils/handle.js'

const usersRouter = Router()

usersRouter.post('/register', registerValidator, wrapAsync(registerController))

usersRouter.post('/login', loginValidator, wrapAsync(loginController)) //tạm thời chưa được

usersRouter.post('/logout', accessTokenValidator, refreshTokenValidator, wrapAsync(logoutController))

usersRouter.get('/verify-email', emailVerifyTokenValidator, wrapAsync(emailVerifyTokenController))

export default usersRouter
