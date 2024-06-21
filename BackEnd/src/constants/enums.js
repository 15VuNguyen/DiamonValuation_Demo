export const UserVerifyStatus = Object.freeze({
  Unverified, // chưa xác thực email, mặc định = 0
  Verified, // đã xác thực email
  Banned, // bị khóa
});

export const TokenType = Object.freeze({
  AccessToken,
  RefreshToken,
  ForgotPasswordToken,
  EmailVerificationToken,
});

export const MediaType = Object.freeze({
  Image, //0
  Video, //1
});
