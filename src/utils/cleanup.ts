import Otp from '../models/otp.model'
import cron from 'node-cron'

// Run every 6 hours
export const startOtpCleanup = () => {
  cron.schedule('0 */6 * * *', async () => {
    try {
      const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000) // 24 hours ago
      await Otp.deleteMany({
        $or: [{ isValid: false }, { expiresAt: { $lt: cutoff } }],
      })
      console.log('[Cleanup] Removed expired or invalid OTPs')
    } catch (error) {
      console.error('[Cleanup] Error during OTP cleanup:', error)
    }
  })
}
