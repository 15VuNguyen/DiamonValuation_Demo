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
import axios from 'axios'
import HTTP_STATUS from '../constants/httpStatus.js'

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

  async resendEmailVerify(user_id, email) {
    //tạo lại email_verify_token
    const email_verify_token = await this._signEmailVerifyToken({
      user_id,
      verify: UserVerifyStatus.Unverified
    })
    //update lại user
    await databaseService.users.updateOne({ _id: new ObjectId(user_id) }, [
      {
        $set: {
          email_verify_token,
          updated_at: '$$NOW'
        }
      }
    ])
    //giả gửi mail, nếu đc thì làm visa (aws, ses)
    //chỗ này sẽ gửi mail
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
      to: email, // Địa chỉ email của người nhận (người dùng đăng ký)
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
    return { message: USERS_MESSAGES.RESEND_EMAIL_VERIFY_SUCCESS }
  }

  async forgotPassword({ user_id, verify }) {
    //tạo ra forgot_password_token
    const forgot_password_token = await this._signForgotPasswordToken({
      user_id,
      verify
    })
    //update lại user
    await databaseService.users.updateOne({ _id: new ObjectId(user_id) }, [
      {
        $set: {
          forgot_password_token,
          updated_at: '$$NOW'
        }
      }
    ])
    //giả gửi mail, nếu đc thì làm visa (aws, ses)
    //gửi mail chỗ này
    console.log(forgot_password_token)
    return { message: USERS_MESSAGES.CHECK_EMAIL_TO_RESET_PASSWORD }
    //check email to reset password
  }

  async resetPassword({ user_id, password }) {
    //dựa vào user_id tìm user và cập nhật lại password
    await databaseService.users.updateOne({ _id: new ObjectId(user_id) }, [
      {
        $set: {
          password: hashPassword(password),
          forgot_password_token: '',
          updated_at: '$$NOW'
        }
      }
    ])
    return { message: USERS_MESSAGES.RESET_PASSWORD_SUCCESS }
  }

  async getMe(user_id) {
    //dựa vào user_id tìm user
    const user = await databaseService.users.findOne(
      { _id: new ObjectId(user_id) },
      {
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0
        }
      }
    )
    return user
  }

  async updateMe(user_id, payload) {
    const _payload = payload.date_of_birth ? { ...payload, date_of_birth: new Date(payload.date_of_birth) } : payload

    //cập nhật _payload lên db
    const user = await databaseService.users.findOneAndUpdate(
      { _id: new ObjectId(user_id) },
      [
        {
          $set: {
            ..._payload,
            updated_at: '$$NOW'
          }
        }
      ],
      {
        returnDocument: 'after',
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0
        }
      }
    )
    return user
  }

  async getProfile(username) {
    //tìm user dựa vào username
    const user = await databaseService.users.findOne(
      { username },
      {
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0,
          create_at: 0,
          update_at: 0
        }
      }
    )
    if (user == null) {
      throw new ErrorWithStatus({
        message: USERS_MESSAGES.USER_NOT_FOUND,
        status: HTTP_STATUS.NOT_FOUND
      })
    }
    return user
  }

  async changePassword(user_id, password) {
    //tìm user thông qua user_id
    //cập nhật lại password và forgot_password_token
    //tất nhiên là lưu password đã hash rồi
    await databaseService.users.updateOne({ _id: new ObjectId(user_id) }, [
      {
        $set: {
          password: hashPassword(password),
          forgot_password_token: '',
          updated_at: '$$NOW'
        }
      }
    ])
    //nếu bạn muốn ngta đổi mk xong tự động đăng nhập luôn thì trả về access_token và refresh_token
    //ở đây mình chỉ cho ngta đổi mk thôi, nên trả về message
    return {
      message: USERS_MESSAGES.CHANGE_PASSWORD_SUCCESS // trong message.ts thêm CHANGE_PASSWORD_SUCCESS: 'Change password success'
    }
  }

  async refreshToken({ user_id, verify, refresh_token, exp }) {
    //tạo ra access và refresh token mới
    const [access_token, new_refresh_token] = await Promise.all([
      this._signAccessToken({ user_id, verify }),
      this._signRefreshToken({ user_id, verify, exp })
    ])
    const { iat } = await this._decodeRefreshToken(refresh_token)
    //vì một người đăng nhập ở nhiều nơi khác nhau, nên họ sẽ có rất nhiều document trong collection refreshTokens
    //ta không thể dùng user_id để tìm document cần update, mà phải dùng token, đọc trong RefreshToken.schema.ts
    await databaseService.refreshTokens.deleteOne({ token: refresh_token }) //xóa refresh
    //insert lại document mới
    await databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: new_refresh_token, exp, iat })
    )
    return { access_token: access_token, refresh_token: new_refresh_token }
  }

  //_getOAuthGoogleToken dùng code nhận đc để yêu cầu google tạo id_token
  async _getOAuthGoogleToken(code) {
    const body = {
      code,
      client_id: process.env.GOOGLE_CLIENT_ID, //khai báo trong .env bằng giá trị trong file json
      client_secret: process.env.GOOGLE_CLIENT_SECRET, //khai báo trong .env bằng giá trị trong file json
      redirect_uri: process.env.GOOGLE_REDIRECT_URI, //khai báo trong .env bằng giá trị trong file json
      grant_type: 'authorization_code'
    }
    //giờ ta gọi api của google, truyền body này lên để lấy id_token
    //ta dùng axios để gọi api `npm i axios`
    const { data } = await axios.post(`https://oauth2.googleapis.com/token`, body, {
      headers: {
        'Content-Type': 'application/json' //kiểu truyền lên là form
      }
    }) //nhận đc response nhưng đã rã ra lấy data
    return {
      access_token: data.access_token,
      id_token: data.id_token
    }
  }

  //dùng id_token để lấy thông tin của người dùng
  async _getGoogleUserInfo(access_token, id_token) {
    //đường dẫn giúp verify access_token và id_token lấy thông tin người dùng
    const { data } = await axios.get(`https://www.googleapis.com/oauth2/v3/userinfo`, {
      params: {
        access_token,
        alt: 'json'
      },
      headers: {
        Authorization: `Bearer ${id_token}`
      }
    })
    //ta chỉ lấy những thông tin cần thiết
    return {
      id: data.id,
      email: data.email,
      email_verified: data.email_verified,
      name: data.name,
      given_name: data.given_name,
      family_name: data.family_name,
      picture: data.picture,
      locale: data.locale
    }
  }

  async oAuth(code) {
    //dùng code lấy bộ token từ google
    const { access_token, id_token } = await this._getOAuthGoogleToken(code)
    const userInfor = await this._getGoogleUserInfo(access_token, id_token)
    //kiểm tra xem user đã verify email chưa
    if (!userInfor.email_verified) {
      throw new ErrorWithStatus({
        message: USERS_MESSAGES.EMAIL_NOT_VERIFIED, // trong message.ts thêm GMAIL_NOT_VERIFIED: 'Gmail not verified'
        status: HTTP_STATUS.BAD_REQUEST //thêm trong HTTP_STATUS BAD_REQUEST:400
      })
    }
    //kiểm tra email đã tồn tại chưa tồn tại trong database của mình chưa
    const user = await databaseService.users.findOne({ email: userInfor.email })
    //nếu có thì nghĩa là client đăng nhập
    if (user) {
      const [access_token, refresh_token] = await this._signAccessAndRefreshTokens({
        user_id: user._id.toString(),
        verify: user.verify
      }) //thêm user_id và verify
      //lưu refresh token vào database
      const { exp, iat } = await this._decodeRefreshToken(refresh_token)
      await databaseService.refreshTokens.insertOne(
        new RefreshToken({ user_id: user._id, token: refresh_token, exp, iat })
      )
      return {
        access_token,
        refresh_token,
        new_user: 0, //đây là user cũ
        verify: user.verify
      }
    } else {
      //random string password
      const password = Math.random().toString(36).slice(1, 15)
      //chưa tồn tại thì cho tạo mới, hàm register(đã viết trước đó) trả về access và refresh token
      const data = await this.register({
        email: userInfor.email,
        name: userInfor.name,
        password: password,
        confirm_password: password,
        date_of_birth: new Date().toISOString()
      })
      return {
        ...data,
        new_user: 1, //đây là user mới
        verify: UserVerifyStatus.Unverified
      }
    }
  }
}

const usersService = new UsersService()
export default usersService
