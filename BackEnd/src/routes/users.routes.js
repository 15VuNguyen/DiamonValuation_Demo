import { Router } from 'express'
import {
  accessTokenValidator,
  changePasswordValidator,
  emailVerifyTokenValidator,
  forgotPasswordValidator,
  loginValidator,
  refreshTokenValidator,
  registerValidator,
  resetPasswordValidator,
  updateMeValidator,
  verifiedUserValidator,
  verifyForgotPasswordTokenValidator
} from '../middlewares/users.middlewares.js'
import {
  changePasswordController,
  emailVerifyTokenController,
  forgotPasswordController,
  getMeController,
  getProfileController,
  loginController,
  logoutController,
  oAuthController,
  refreshController,
  registerController,
  resendEmailVerifyController,
  resetPasswordController,
  updateMeController,
  verifyForgotPasswordTokenController
} from '../controllers/users.controllers.js'
import { wrapAsync } from '../utils/handle.js'
import { filterMiddleware } from '../middlewares/common.middlewares.js'

const usersRouter = Router()

usersRouter.post('/register', registerValidator, wrapAsync(registerController))

usersRouter.post('/login', loginValidator, wrapAsync(loginController)) //tạm thời chưa được

usersRouter.post('/logout', accessTokenValidator, refreshTokenValidator, wrapAsync(logoutController))

usersRouter.get('/verify-email', emailVerifyTokenValidator, wrapAsync(emailVerifyTokenController))

usersRouter.post('/resend-verify-email', accessTokenValidator, wrapAsync(resendEmailVerifyController))

usersRouter.post('/forgot-password', forgotPasswordValidator, wrapAsync(forgotPasswordController))

//nếu như mai mốt có giao diện thì thử test gửi mail qua method:get bằng nodemailer giống verify-email
//để gửi mail qua method:get thì cần phải thêm query param vào url
//ví dụ: http://localhost:3000/users/verify-forgot-password?forgot_password_token=token
//và lấy token từ query param
//chuyển qua reset password page
//sau đó gửi post request với token và password mới
//nếu token hợp lệ thì cho phép reset password
//nếu token không hợp lệ thì báo lỗi
//nếu token hết hạn thì báo lỗi
//nếu token đã sử dụng rồi thì báo lỗi
usersRouter.post(
  '/verify-forgot-password',
  verifyForgotPasswordTokenValidator,
  wrapAsync(verifyForgotPasswordTokenController)
)

//tới được reset-password là đã qua đc forgot-password và verify-forgot-password
//báo thành công và frontend sẽ chuyển hướng người dùng đến trang reset password
//kiểm tra lại verifyForgotPasswordTokenValidator 1 lần nữa
usersRouter.post(
  '/reset-password',
  resetPasswordValidator,
  verifyForgotPasswordTokenValidator,
  wrapAsync(resetPasswordController)
)

usersRouter.get('/me', accessTokenValidator, wrapAsync(getMeController))

usersRouter.patch(
  '/me',
  accessTokenValidator,
  verifiedUserValidator,
  filterMiddleware(['name', 'date_of_birth', 'bio', 'location', 'website', 'username', 'avatar', 'cover_photo']), //lọc ra những key cần thiết để update
  updateMeValidator,
  wrapAsync(updateMeController)
)

/*
des: get profile của user khác bằng unsername
path: '/:username'
method: get
không cần header vì, chưa đăng nhập cũng có thể xem
*/
usersRouter.get('/:username', wrapAsync(getProfileController))

/*
  des: change password
  path: '/change-password'
  method: PUT
  headers: {Authorization: Bearer <access_token>}
  Body: {old_password: string, password: string, confirm_password: string}
*/
usersRouter.put(
  '/change-password',
  accessTokenValidator,
  verifiedUserValidator,
  changePasswordValidator,
  wrapAsync(changePasswordController)
)

/*
  des: refreshtoken
  path: '/refresh-token'
  method: POST
  Body: {refresh_token: string}
g}
  */
//khi access_token hết hạn thì frontend gọi route refresh_token để lấy access_token mới
// và refresh_token có thời hạn bằng thời hạn cũ
usersRouter.post('/refresh-token', refreshTokenValidator, wrapAsync(refreshController))

usersRouter.get('/oauth/google', wrapAsync(oAuthController))

export default usersRouter
