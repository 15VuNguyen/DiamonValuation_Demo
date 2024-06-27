import { ObjectId } from 'mongodb'
import { UserVerifyStatus } from '../../constants/enums.js'

//đặt interface vì theo chuẩn ts thôi, chứ làm thực tế thì khác

export default class UserSchema {
  _id = new ObjectId()
  name = ''
  email = ''
  date_of_birth = new Date()
  password = ''
  created_at = new Date()
  updated_at = new Date()
  email_verify_token = ''
  forgot_password_token = ''
  verify = UserVerifyStatus.Unverified

  bio = ''
  location = ''
  website = ''
  username = ''
  avatar = ''
  cover_photo = ''
  constructor(user) {
    const date = new Date() //tạo này cho ngày created_at updated_at bằng nhau
    this._id = user?._id ?? new ObjectId() // tự tạo id
    this.name = user.name || '' // nếu người dùng tạo mà k truyền ta sẽ để rỗng
    this.email = user.email
    this.date_of_birth = user.date_of_birth || new Date()
    this.password = user.password
    this.created_at = user.created_at || date
    this.updated_at = user.updated_at || date
    this.email_verify_token = user.email_verify_token || ''
    this.forgot_password_token = user.forgot_password_token || ''
    this.verify = user.verify || UserVerifyStatus.Unverified

    this.bio = user.bio || ''
    this.location = user.location || ''
    this.website = user.website || ''
    this.username = user.username || ''
    this.avatar = user.avatar || ''
    this.cover_photo = user.cover_photo || ''
  }
}

// const UserSchema = new User()
// export default UserSchema
