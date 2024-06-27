import { Collection, MongoClient, ServerApiVersion } from 'mongodb'
import { config } from 'dotenv'

config()

const uri =
  'mongodb+srv://zunguyen1505:boyboyboy@diamonddemo.bvrjnnl.mongodb.net/?retryWrites=true&w=majority&appName=diamondDemo'

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
class DatabaseService {
  _client
  _db
  constructor() {
    this._client = new MongoClient(uri)
    this._db = this._client.db(process.env.DB_NAME)
  }
  async connect() {
    try {
      await this._db.command({ ping: 1 })
      console.log('Pinged your deployment. You successfully connected to MongoDB!')
    } catch (error) {
      console.log(error)
      throw error
    }
  }
  get users() {
    try {
      // const users = this._db.collection(process.env.DB_USERS_COLLECTION)
      return this._db.collection(process.env.DB_USERS_COLLECTION)
      //vào db lấy ra collection users, và vì chuỗi truyền vào có thể là undefined nên mình phải rằng buộc nó là string 'thử xóa as string để thấy lỗi'
    } catch (error) {
      console.log(error + 'lỗi ở database service - get users')
      throw error
    }
  }

  async indexUsers() {
    await this.users.createIndex({ email: 1 }, { unique: true }) //register
    await this.users.createIndex({ username: 1 }, { unique: true }) //getProfile
    await this.users.createIndex({ email: 1, password: 1 }) //login
  }

  get refreshTokens() {
    try {
      return this._db.collection(process.env.DB_REFRESH_TOKENS_COLLECTION)
    } catch (error) {
      console.log(error + 'lỗi ở database service - get refresh token')
    }
  }

  // get followers(): Collection<Follower> {
  //   return this.db.collection(process.env.DB_FOLLOWERS_COLLECTION as string)
  // }
}

const databaseService = new DatabaseService()
export default databaseService
