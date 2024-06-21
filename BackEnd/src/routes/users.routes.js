import { Router } from 'express'
import { loginValidator } from '../middlewares/users.middlewares.js'
import { loginController } from '../controllers/users.controllers.js'
import { wrapAsync } from '../utils/handle.js'

const usersRouter = Router()

usersRouter.post('/login', loginValidator, wrapAsync(loginController)) //tạm thời chưa được

export default usersRouter
