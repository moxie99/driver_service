import mongoose, { Schema, Document } from 'mongoose'

export interface IPendingDriver extends Document {
  name: string
  email: string
  password: string
  phone: string
  registrationStatus:
    | 'unconfirmed'
    | 'confirmed'
    | 'kyc_pending'
    | 'kyc_verified'
  createdAt: Date
}

const PendingDriverSchema: Schema = new Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, required: true },
  registrationStatus: {
    type: String,
    enum: ['unconfirmed', 'confirmed', 'kyc_pending', 'kyc_verified'],
    default: 'unconfirmed',
  },
  createdAt: { type: Date, default: Date.now },
})

export default mongoose.model<IPendingDriver>(
  'PendingDriver',
  PendingDriverSchema
)
