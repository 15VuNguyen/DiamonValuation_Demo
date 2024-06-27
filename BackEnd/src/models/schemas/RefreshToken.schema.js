//interface dùng để định nghĩa kiểu dữ liệu
//interface không có thể dùng để tạo ra đối tượng
//class dùng để tạo ra đối tượng
//class sẽ thông qua interface
//thứ tự dùng như sau
//class này < databse < service < controller < route < app.ts < server.ts < index.ts

export default class RefreshToken {
  constructor({ _id, token, created_at, user_id, exp, iat }) {
    this._id = _id
    this.token = token
    this.created_at = created_at || new Date()
    this.user_id = user_id
    this.exp = new Date(exp * 1000) //từ epoch time sang date
    this.iat = new Date(iat * 1000)
  }
}
