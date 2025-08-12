import express from 'express'
import mongoose from 'mongoose'
import driverRoutes from '../src/routes/driver.routes'
import dotenv from 'dotenv'
import { startOtpCleanup } from './utils/cleanup'
import categoryRoutes from '../src/routes/category.routes'
dotenv.config()

const app = express()
app.use(express.json())
app.use('/api/drivers', driverRoutes)
app.use('/api', categoryRoutes)

const startServer = async () => {
  try {
    await mongoose.connect(
      process.env.MONGODB_URI_DRIVER ||
        'mongodb://localhost:27017/haulage-driver-service'
    )
    startOtpCleanup()
    console.log('Connected to MongoDB')

    // Drop problematic index
    await mongoose
      .model('Driver')
      .collection.dropIndex('licenseNumber_1')
      .catch((err) => {
        if (err.codeName !== 'IndexNotFound') throw err
      })

    // Ensure correct indexes
    await mongoose.model('Driver').ensureIndexes()
    console.log('Indexes ensured')

    const PORT = process.env.PORT || 3002
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error)
    process.exit(1)
  }
}

mongoose.set('debug', true)
startServer()
