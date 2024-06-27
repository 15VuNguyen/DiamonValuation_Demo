import { hashPassword } from '../utils/crypto.js'
import { checkSchema } from 'express-validator'
import { validate } from '../utils/validation.js'
import { USERS_MESSAGES } from '../constants/messages.js'
import HTTP_STATUS from '../constants/httpStatus.js'
import { ErrorWithStatus } from '../models/Errors.js'
import usersService from '../services/users.services.js'
import databaseService from '../services/database.service.js'
import { verifyToken } from '../utils/jwt.js'
import capitalize from 'lodash'
import JsonWebTokenError from 'jsonwebtoken'

const passwordSchema = {
  notEmpty: {
    errorMessage: USERS_MESSAGES.PASSWORD_IS_REQUIRED
  },
  isString: {
    errorMessage: USERS_MESSAGES.PASSWORD_MUST_BE_A_STRING
  },
  isLength: {
    options: {
      min: 8,
      max: 50
    },
    errorMessage: USERS_MESSAGES.PASSWORD_LENGTH_MUST_BE_FROM_8_TO_50
  },
  isStrongPassword: {
    options: {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1
    },
    errorMessage: USERS_MESSAGES.PASSWORD_MUST_BE_STRONG
  }
}

const confirmPasswordSchema = {
  notEmpty: {
    errorMessage: USERS_MESSAGES.CONFIRM_PASSWORD_IS_REQUIRED
  },
  isString: {
    errorMessage: USERS_MESSAGES.CONFIRM_PASSWORD_MUST_BE_A_STRING
  },
  isLength: {
    options: {
      min: 8,
      max: 50
    },
    errorMessage: USERS_MESSAGES.CONFIRM_PASSWORD_LENGTH_MUST_BE_FROM_8_TO_50
  },
  isStrongPassword: {
    options: {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1
    },
    errorMessage: USERS_MESSAGES.CONFIRM_PASSWORD_MUST_BE_STRONG
  },
  custom: {
    options: (value, { req }) => {
      if (value !== req.body.password) {
        throw new Error(USERS_MESSAGES.CONFIRM_PASSWORD_MUST_BE_THE_SAME_AS_PASSWORD)
      }
      return true
    }
  }
}

const nameSchema = {
  notEmpty: {
    errorMessage: USERS_MESSAGES.NAME_IS_REQUIRED
  },
  isString: {
    errorMessage: USERS_MESSAGES.NAME_MUST_BE_A_STRING
  },
  trim: true,
  isLength: {
    options: {
      min: 1,
      max: 100
    },
    errorMessage: USERS_MESSAGES.NAME_LENGTH_MUST_BE_FROM_1_TO_100
  }
}

const dateOfBirthSchema = {
  isISO8601: {
    options: {
      strict: true,
      strictSeparator: true
    },
    errorMessage: USERS_MESSAGES.DATE_OF_BIRTH_BE_ISO8601
  }
}

const userIdSchema = {
  custom: {
    options: async (value, { req }) => {
      //check value có phải objectId hay không?
      if (!ObjectId.isValid(value)) {
        throw new ErrorWithStatus({
          message: USERS_MESSAGES.INVALID_USER_ID,
          status: HTTP_STATUS.NOT_FOUND
        })
      }
      //vào database tìm user đó xem có không ?
      const user = await databaseService.users.findOne({
        _id: new ObjectId(value)
      })
      if (user === null) {
        throw new ErrorWithStatus({
          message: USERS_MESSAGES.USER_NOT_FOUND, //trong message.ts thêm FOLLOWED_USER_NOT_FOUND: 'Followed user not found'
          status: HTTP_STATUS.NOT_FOUND
        })
      }
      //nếu vướt qua hết if thì return true
      return true
    }
  }
}

export const loginValidator = validate(
  checkSchema(
    {
      email: {
        notEmpty: {
          errorMessage: USERS_MESSAGES.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: USERS_MESSAGES.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            //dựa vào email và password tìm đối tượng tuong ứng trong db
            const user = await databaseService.users.findOne({
              email: value,
              password: hashPassword(req.body.password)
            })
            if (user === null) {
              throw new Error(USERS_MESSAGES.EMAIL_OR_PASSWORD_IS_INCORRECT)
            }
            req.user = user
            return true
          }
        }
      },
      password: {
        notEmpty: {
          errorMessage: USERS_MESSAGES.PASSWORD_IS_REQUIRED
        },
        isString: {
          errorMessage: USERS_MESSAGES.PASSWORD_MUST_BE_A_STRING
        },
        isLength: {
          options: {
            min: 8,
            max: 50
          },
          errorMessage: USERS_MESSAGES.PASSWORD_LENGTH_MUST_BE_FROM_8_TO_50
        },
        isStrongPassword: {
          options: {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1
          },
          errorMessage: USERS_MESSAGES.PASSWORD_MUST_BE_STRONG
        }
      }
    },
    ['body']
  )
)

export const registerValidator = validate(
  checkSchema(
    {
      name: nameSchema,
      email: {
        notEmpty: {
          errorMessage: USERS_MESSAGES.EMAIL_IS_REQUIRED
        },
        isEmail: {
          errorMessage: USERS_MESSAGES.EMAIL_IS_INVALID
        },
        trim: true,
        custom: {
          options: async (value, { req }) => {
            const isExist = await usersService.checkEmailExist(value)
            if (isExist) {
              throw new Error('Email already exists')
            }
            return true
          }
        }
      },
      password: passwordSchema,
      confirm_password: confirmPasswordSchema,
      date_of_birth: dateOfBirthSchema
    },
    ['body']
  )
)

export const accessTokenValidator = validate(
  checkSchema(
    {
      Authorization: {
        trim: true,
        custom: {
          //value là giá trị của Authorization, req là req của client gữi lên server
          options: async (value, { req }) => {
            //value của Authorization là chuỗi "Bearer <access_token>"
            //ta sẽ tách chuỗi đó ra để lấy access_token bằng cách split
            const accessToken = value.split(' ')[1]
            //nếu nó có truyền lên , mà lại là chuỗi rỗng thì ta sẽ throw error
            if (!accessToken) {
              //throw new Error(USERS_MESSAGES.ACCESS_TOKEN_IS_REQUIRED)  //này trả ra 422(k hay)
              // nếu kh có accessToken thì ném lỗi 401
              throw new ErrorWithStatus({
                message: USERS_MESSAGES.ACCESS_TOKEN_IS_REQUIRED,
                status: HTTP_STATUS.UNAUTHORIZED //401
              })
            }
            try {
              //nếu có accessToken thì mình phải verify AccesToken
              const decoded_authorization = await verifyToken({
                token: accessToken,
                secretOrPublicKey: process.env.JWT_SECRET_ACCESS_TOKEN
              })
              // lấy ra decoded_authorization(layload), lưu vào req, để dùng dần
              req.decoded_authorization = decoded_authorization
            } catch (error) {
              throw new ErrorWithStatus({
                message: capitalize(error.message),
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            return true
          }
        }
      }
    },
    ['headers']
  )
)

export const refreshTokenValidator = validate(
  checkSchema(
    {
      refresh_token: {
        trim: true,
        custom: {
          options: async (value, { req }) => {
            //verify refresh_token để lấy decoded_refresh_token
            try {
              const [decoded_refresh_token, refresh_token] = await Promise.all([
                verifyToken({ token: value, secretOrPublicKey: process.env.JWT_SECRET_REFRESH_TOKEN }),
                databaseService.refreshTokens.findOne({
                  token: value
                })
              ])

              if (refresh_token === null) {
                throw new ErrorWithStatus({
                  message: USERS_MESSAGES.USED_REFRESH_TOKEN_OR_NOT_EXIST,
                  status: HTTP_STATUS.UNAUTHORIZED
                })
              }
              req.decoded_refresh_token = decoded_refresh_token
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: capitalize(error.message),
                  status: HTTP_STATUS.UNAUTHORIZED
                })
              }
              throw error
            }
            return true
          }
        }
      }
    },
    ['body']
  )
)

export const emailVerifyTokenValidator = validate(
  checkSchema(
    {
      email_verify_token: {
        trim: true,
        custom: {
          options: async (value, { req }) => {
            //kiểm tra người dùng có truyền lên email_verify_token hay không
            if (!value) {
              throw new ErrorWithStatus({
                message: USERS_MESSAGES.EMAIL_VERIFY_TOKEN_IS_REQUIRED,
                status: HTTP_STATUS.UNAUTHORIZED
              })
            }
            try {
              //verify email_verify_token để lấy decoded_email_verify_token
              const decoded_email_verify_token = await verifyToken({
                token: value,
                secretOrPublicKey: process.env.JWT_SECRET_EMAIL_VERIFY_TOKEN
              })
              //sau khi verify thành công ta đc payload của email_verify_token: decoded_email_verify_token
              req.decoded_email_verify_token = decoded_email_verify_token
            } catch (error) {
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: capitalize(error.message),
                  status: HTTP_STATUS.UNAUTHORIZED
                })
              }
              throw error
            }
            return true
          }
        }
      }
    },
    ['query']
  )
)
