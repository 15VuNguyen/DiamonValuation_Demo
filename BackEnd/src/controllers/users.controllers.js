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
