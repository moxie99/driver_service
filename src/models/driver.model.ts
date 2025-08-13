import mongoose, { Schema, Document } from 'mongoose'
import { KycData } from '../types'

export interface IDriver extends Document {
  name: string
  email: string
  password: string
  phone: string
  vehicleType?: string
  licenseNumber?: string
  status: 'pending' | 'approved' | 'suspended'
  kycStatus: 'pending' | 'processing' | 'confirmed' | 'rejected'
  kycData?: KycData
  isAdmin: boolean
}

const DriverSchema: Schema = new Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    phone: { type: String, required: true },
    vehicleType: { type: String, default: '' },
    licenseNumber: { type: String, default: '' },
    status: {
      type: String,
      enum: ['pending', 'approved', 'suspended'],
      default: 'pending',
    },
    kycStatus: {
      type: String,
      enum: ['pending', 'processing', 'confirmed', 'rejected'],
      default: 'pending',
    },
    kycData: {
      location: { type: String },
      address: { type: String },
      officeAddress: { type: String },
      dateOfBirth: { type: Date },
      gender: { type: String, enum: ['male', 'female', 'other'] },
      selfie: { type: String },
      driverLicensePicture: { type: String },
      vehicleInformationPicture: { type: String },
      insurancePicture: { type: String },
      vehicleInspectionDocumentPicture: { type: String },
      daysOfAvailability: [
        {
          type: String,
          enum: [
            'Monday',
            'Tuesday',
            'Wednesday',
            'Thursday',
            'Friday',
            'Saturday',
            'Sunday',
          ],
        },
      ],
      startTime: { type: String },
      endTime: { type: String },
      serviceArea: { type: String },
      specialNote: { type: String },
      categories: { type: [String] },
    },
    isAdmin: { type: Boolean, default: false },
  },
  { timestamps: true }
)

// Remove existing index on licenseNumber if it exists
DriverSchema.index({ licenseNumber: 1 }, { unique: false, sparse: false })

// Ensure unique index on kyc.licenseNumber when set
DriverSchema.index({ 'kyc.licenseNumber': 1 }, { unique: true, sparse: true })

export default mongoose.model<IDriver>('Driver', DriverSchema)
