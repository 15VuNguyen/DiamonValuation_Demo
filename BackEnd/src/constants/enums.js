export const UserVerifyStatus = Object.freeze({
  Unverified: 0, // chưa xác thực email, mặc định = 0
  Verified: 1, // đã xác thực email
  Banned: 2 // bị khóa
})

export const TokenType = Object.freeze({
  AccessToken: 0,
  RefreshToken: 1,
  ForgotPasswordToken: 2,
  EmailVerificationToken: 3
})

export const MediaType = Object.freeze({
  Image: 0, //0
  Video: 1 //1
})
