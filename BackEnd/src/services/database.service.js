import { MongoClient, ServerApiVersion } from 'mongodb'
const uri =
  'mongodb+srv://zunguyen1505:boyboyboy@diamonddemo.bvrjnnl.mongodb.net/?retryWrites=true&w=majority&appName=diamondDemo'

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri)

export async function run() {
  try {
    await client.db('admin').command({ ping: 1 })
    console.log('Pinged your deployment. You successfully connected to MongoDB!')
  } catch (error) {
    console.log(error)
  }
}
