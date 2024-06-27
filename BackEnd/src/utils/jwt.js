import jwt from 'jsonwebtoken'

//làm hàm nhận vào payload, privateKey, options và từ đó ký tên

export const signToken = ({ payload, privateKey, options = { algorithm: 'HS256' } }) => {
  return new Promise((resolve, reject) => {
    jwt.sign(payload, privateKey, options, (err, token) => {
      if (err) throw reject(err)
      resolve(token)
    })
  })
}

// hàm nhận vào token, và secretOrPublicKey ?
export const verifyToken = ({ token, secretOrPublicKey }) => {
  return new Promise((resolve, reject) => {
    jwt.verify(token, secretOrPublicKey, (error, decoded) => {
      if (error) throw reject(error + 'error in verifyToken function')
      resolve(decoded)
    })
  })
}
