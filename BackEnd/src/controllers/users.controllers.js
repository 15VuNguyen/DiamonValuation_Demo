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
