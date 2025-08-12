import mongoose, { Schema, Document } from 'mongoose'

export interface IOtp extends mongoose.Document {
  email: string
  otp: string
  expiresAt: Date
  lastSent: Date
  isValid: boolean
  purpose: 'registration' | 'password_reset' | 'confirm_onboarding'
}

const OtpSchema: Schema = new Schema({
  email: { type: String, required: true, unique: true },
  otp: { type: String, required: true },
  expiresAt: { type: Date, required: true, index: { expires: '5m' } },
  lastSent: { type: Date, required: true },
  isValid: { type: Boolean, required: true, default: true },
  purpose: {
    type: String,
    enum: ['registration', 'password_reset', 'confirm_onboarding'],
    required: true,
  },
})

// Automatically remove expired OTPs
OtpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })

export default mongoose.model<IOtp>('Otp', OtpSchema)
