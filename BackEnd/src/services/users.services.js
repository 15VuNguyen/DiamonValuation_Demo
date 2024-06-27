import { ObjectId } from 'mongodb'
import { TokenType, UserVerifyStatus } from '../constants/enums.js'
import RefreshToken from '../models/schemas/RefreshToken.schema.js'
import { hashPassword } from '../utils/crypto.js'
import { signToken, verifyToken } from '../utils/jwt.js'
// import User from '../models/schemas/User.schema.js'
import UserSchema from '../models/schemas/User.schema.js'
import databaseService from './database.service.js'
import { USERS_MESSAGES } from '../constants/messages.js'
import nodemailer from 'nodemailer'

// const { DatabaseService } = require('./database.service')

class UsersService {
  _signEmailVerifyToken({ user_id, verify }) {
    return signToken({
      payload: { user_id, token_type: TokenType.EmailVerificationToken, verify },
      options: { expiresIn: process.env.EMAIL_VERIFY_TOKEN_EXPIRE_IN },
      privateKey: process.env.JWT_SECRET_EMAIL_VERIFY_TOKEN
    })
  }

  _decodeRefreshToken(refresh_token) {
    return verifyToken({
      token: refresh_token,
      secretOrPublicKey: process.env.JWT_SECRET_REFRESH_TOKEN
    })
  }

  //hàm nhận vào user_id và bỏ vào payload để tạo access_token
  _signAccessToken({ user_id, verify }) {
    return signToken({
      payload: { user_id, token_type: TokenType.AccessToken, verify },
      options: { expiresIn: process.env.ACCESS_TOKEN_EXPIRE_IN },
      privateKey: process.env.JWT_SECRET_ACCESS_TOKEN
    })
  }
  //hàm nhận vào user_id và bỏ vào payload để tạo refresh_token
  _signRefreshToken({ user_id, verify, exp }) {
    if (exp) {
      return signToken({
        payload: { user_id, token_type: TokenType.RefreshToken, verify, exp },
        privateKey: process.env.JWT_SECRET_REFRESH_TOKEN
      })
    } else {
      return signToken({
        payload: { user_id, token_type: TokenType.RefreshToken, verify },
        options: { expiresIn: process.env.REFRESH_TOKEN_EXPIRE_IN },
        privateKey: process.env.JWT_SECRET_REFRESH_TOKEN
      })
    }
  }

  //hàm signForgotPasswordToken
  _signForgotPasswordToken({ user_id, verify }) {
    return signToken({
      payload: { user_id, token_type: TokenType.ForgotPasswordToken, verify },
      options: { expiresIn: process.env.FORGOT_PASSWORD_TOKEN_EXPIRE_IN },
      privateKey: process.env.JWT_SECRET_FORGOT_PASSWORD_TOKEN
    })
  }

  //ký access_token và refresh_token
  _signAccessAndRefreshTokens({ user_id, verify }) {
    return Promise.all([this._signAccessToken({ user_id, verify }), this._signRefreshToken({ user_id, verify })])
  }

  async checkEmailExist(email) {
    const user = await databaseService.users.findOne({ email })
    return Boolean(user)
  }

  async register(payload) {
    const user_id = new ObjectId()
    const email_verify_token = await this._signEmailVerifyToken({
      user_id: user_id.toString(),
      verify: UserVerifyStatus.Unverified
    })
    const result = await databaseService.users.insertOne(
      new UserSchema({
        ...payload,
        _id: user_id,
        username: `user${user_id.toString()}`,
        email_verify_token,
        date_of_birth: new Date(payload.date_of_birth),
        password: hashPassword(payload.password)
      })
    )
    const [access_token, refresh_token] = await this._signAccessAndRefreshTokens({
      user_id: user_id.toString(),
      verify: UserVerifyStatus.Unverified
    })

    const { exp, iat } = await this._decodeRefreshToken(refresh_token)

    //lưu refresh_token vào db
    await databaseService.refreshTokens.insertOne(
      new RefreshToken({
        token: refresh_token,
        user_id: new ObjectId(user_id),
        exp,
        iat
      })
    )
    //giả gửi mail, nếu đc thì làm visa (aws, ses)
    //chỗ này để gửi mail
    //test gửi mail
    let transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_APP, // Thay thế bằng email của bạn
        pass: process.env.EMAIL_PASSWORD_APP // Thay thế bằng mật khẩu của bạn
      }
    })

    // Cấu hình và gửi email
    const verifyURL = `http://localhost:${process.env.PORT}/users/verify-email?email_verify_token=${email_verify_token}` // Đường dẫn xác nhận email
    let mailOptions = {
      from: process.env.EMAIL_APP, // Thay thế bằng email của bạn
      to: payload.email, // Địa chỉ email của người nhận (người dùng đăng ký)
      subject: 'Xác nhận đăng ký',
      text: 'Nội dung email xác nhận đăng ký...', // Hoặc sử dụng `html` để tạo nội dung email dạng HTML
      html: `<p>Nhấn vào <a href="${verifyURL}">đây</a> để xác nhận đăng ký.</p>` // Sử dụng HTML để tạo nội dung email
    }

    // Gửi email
    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error)
        // Xử lý lỗi gửi email ở đây
      } else {
        console.log('Email sent: ' + info.response)
        // Xử lý thành công gửi email ở đây
      }
    })
    //test gửi mail
    console.log(email_verify_token)
    return { access_token, refresh_token }
  }

  async login({ user_id, verify }) {
    //dùng user_id tạo access_token và refresh_token
    const [access_token, refresh_token] = await this._signAccessAndRefreshTokens({
      user_id,
      verify
    })
    const { exp, iat } = await this._decodeRefreshToken(refresh_token)

    //lưu refresh_token vào db
    await databaseService.refreshTokens.insertOne(
      new RefreshToken({
        token: refresh_token,
        user_id: new ObjectId(user_id),
        exp,
        iat
      })
    )
    return { access_token, refresh_token }
  }

  async logout(refresh_token) {
    //xóa refresh_token khỏi db
    await databaseService.refreshTokens.deleteOne({ token: refresh_token })
    return { message: USERS_MESSAGES.LOGOUT_SUCCESS }
  }

  async verifyEmail(user_id) {
    //update lại user
    await databaseService.users.updateOne({ _id: new ObjectId(user_id) }, [
      {
        $set: {
          verify: UserVerifyStatus.Verified,
          email_verify_token: '',
          updated_at: '$$NOW'
        }
      }
    ])
    //tạo ra access_token và refresh_token
    const [access_token, refresh_token] = await this._signAccessAndRefreshTokens({
      user_id,
      verify: UserVerifyStatus.Verified
    })
    const { exp, iat } = await this._decodeRefreshToken(refresh_token)
    //lưu refresh_token vào db
    await databaseService.refreshTokens.insertOne(
      new RefreshToken({
        token: refresh_token,
        user_id: new ObjectId(user_id),
        exp,
        iat
      })
    )
    return { access_token, refresh_token }
  }
}

const usersService = new UsersService()
export default usersService
