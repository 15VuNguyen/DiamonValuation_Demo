import express from 'express'
import { config } from 'dotenv'
import usersRouter from './routes/users.routes.js'
import { run } from './services/database.service.js'

config()
run().catch(console.dir)

const app = express()
const PORT = process.env.PORT || 4000
app.use(express.json())

app.get('/', (req, res) => {
  res.send('hello world nguyen')
})
app.use('/users', usersRouter)

app.listen(PORT, () => {
  console.log(`Project này đang chạy trên post ${PORT}`)
})
