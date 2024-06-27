import { ObjectId } from 'mongodb'
import { USERS_MESSAGES } from '../constants/messages.js'
import databaseService from '../services/database.service.js'
import usersService from '../services/users.services.js'
import { UserVerifyStatus } from '../constants/enums.js'
import { ErrorWithStatus } from '../models/Errors.js'
import HTTP_STATUS from '../constants/httpStatus.js'

export const loginController = async (req, res) => {
  //lấy user_id từ user của req
  const user = req.user
  const user_id = user._id

  //dùng user_id tạo access_token và refresh_token
  const result = await usersService.login({
    user_id: user_id.toString(),
    verify: user.verify
  })
  //res về access_token và refresh_token cho client
  res.json({
    message: USERS_MESSAGES.LOGIN_SUCCESS,
    result
  })
}

export const registerController = async (req, res) => {
  const result = await usersService.register(req.body)
  res.json({
    message: USERS_MESSAGES.REGISTER_SUCCESS,
    result
  })
}

export const logoutController = async (req, res) => {
  const { refresh_token } = req.body
  //logout sẽ nhận vào refresh_token để tìm và xóa
  const result = await usersService.logout(refresh_token)
  res.json(result)
}

export const emailVerifyTokenController = async (req, res) => {
  //nếu mà code vào đc đây nghĩa là email_verify_token hợp lệ
  //và mình đã lấy đc decoded_email_verify_token từ middleware
  const { user_id } = req.decoded_email_verify_token
  //dựa vào user_id tìm user và xem thử nó đã verify email chưa
  const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
  if (user === null) {
    throw new ErrorWithStatus({
      message: USERS_MESSAGES.USER_NOT_FOUND,
      status: 404
    })
  }
  if (user.verify === UserVerifyStatus.Verified && user.email_verify_token === '') {
    return res.json({
      message: USERS_MESSAGES.EMAIL_ALREADY_VERIFIED_BEFORE
    })
  }
  //nếu mà kh khớp email_verify_token thì sẽ báo lỗi
  if (user.email_verify_token !== req.query.email_verify_token) {
    throw new ErrorWithStatus({
      message: USERS_MESSAGES.EMAIL_VERIFY_TOKEN_IS_INCORRECT,
      status: HTTP_STATUS.UNAUTHORIZED
    })
  }
  //nếu mà xuống đc đây có nghĩa là user chưa verify
  //mình sẽ update lại user đó
  const result = await usersService.verifyEmail(user_id)
  return res.json({
    message: USERS_MESSAGES.VERIFY_EMAIL_SUCCESS,
    result
  })
}

export const resendEmailVerifyController = async (req, res) => {
  //nếu vào đc đây có nghĩa là access_token hợp lệ
  // và mình đã lấy đc decoded_authorization từ middleware
  const { user_id } = req.decoded_authorization
  //dựa vào user_id tìm user và xem thử nó đã verify email chưa
  const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })
  if (user === null) {
    throw new ErrorWithStatus({
      message: USERS_MESSAGES.USER_NOT_FOUND,
      status: 404
    })
  }
  //nếu đã verify rồi thì kh cần verify nữa
  if (user.verify === UserVerifyStatus.Verified && user.email_verify_token === '') {
    return res.json({
      message: USERS_MESSAGES.EMAIL_ALREADY_VERIFIED_BEFORE
    })
  }
  if (user.verify === UserVerifyStatus.Banned) {
    throw new ErrorWithStatus({
      message: USERS_MESSAGES.USER_BANNED,
      status: HTTP_STATUS.FORBIDDEN
    })
  }
  //user này thật sự chưa verify: mình sẽ tạo lại email_verify_token,
  //cập nhật lại user
  const email = user.email // lấy để biết email nào để quay resendEmail gửi lại
  const result = await usersService.resendEmailVerify(user_id, email)
  return res.json(result)
}

export const forgotPasswordController = async (req, res) => {
  //lấy user_id từ user của req
  const { _id, verify } = req.user
  //dùng _id tìm và cập nhật lại user thêm vào forgot_password_token
  const result = await usersService.forgotPassword({ user_id: _id.toString(), verify })
  return res.json(result)
}

export const verifyForgotPasswordTokenController = async (req, res) => {
  return res.json({
    message: USERS_MESSAGES.VERIFY_FORGOT_PASSWORD_TOKEN_SUCCESS
  })
}

export const resetPasswordController = async (req, res) => {
  //muốn đổi mật khẩu thì cần user_id và password mới
  const { user_id } = req.decoded_forgot_password_token
  const { password } = req.body

  //cập nhật
  const result = await usersService.resetPassword({ user_id, password })
  return res.json(result)
}

export const getMeController = async (req, res) => {
  //muốn lấy profile của mình thì phải có user_id của mình
  const { user_id } = req.decoded_authorization
  //tìm user dựa vào user_id
  const user = await usersService.getMe(user_id)
  return res.json({
    message: USERS_MESSAGES.GET_ME_SUCCESS,
    result: user
  })
}

export const updateMeController = async (req, res) => {
  //muốn update profile của mình thì phải có user_id của mình
  const { user_id } = req.decoded_authorization
  const { body } = req
  //update lại user
  const result = await usersService.updateMe(user_id, body)
  return res.json({
    message: USERS_MESSAGES.UPDATE_ME_SUCCESS,
    result
  })
}

export const getProfileController = async (req, res) => {
  //tìm user theo username
  const { username } = req.params
  const user = await usersService.getProfile(username)
  return res.json({
    message: USERS_MESSAGES.GET_PROFILE_SUCCESS,
    result: user
  })
}

export const changePasswordController = async (req, res, next) => {
  const { user_id } = req.decoded_authorization //lấy user_id từ decoded_authorization của access_token
  const { password } = req.body //lấy old_password và password từ req.body
  const result = await usersService.changePassword(user_id, password) //chưa code changePassword
  return res.json(result)
}

export const refreshController = async (req, res, next) => {
  // khi qua middleware refreshTokenValidator thì ta đã có decoded_refresh_token
  //chứa user_id và token_type
  //ta sẽ lấy user_id để tạo ra access_token và refresh_token mới
  const { refresh_token } = req.body
  const { user_id, verify, exp } = req.decoded_refresh_token //lấy refresh_token từ req.body
  const result = await usersService.refreshToken({ user_id, verify, refresh_token, exp }) //refreshToken chưa code
  return res.json({
    message: USERS_MESSAGES.REFRESH_TOKEN_SUCCESS, //message.ts thêm  REFRESH_TOKEN_SUCCESS: 'Refresh token success',
    result
  })
}

export const oAuthController = async (req, res, next) => {
  const { code } = req.query // lấy code từ query params
  const { access_token, refresh_token, new_user } = await usersService.oAuth(code) //oAuth tạo sau
  const urlRedirect = `${process.env.CLIENT_REDIRECT_CALLBACK}?access_token=${access_token}&refresh_token=${refresh_token}&new_user=${new_user}`
  return res.redirect(urlRedirect)
}
