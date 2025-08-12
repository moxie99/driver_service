import { Request } from 'express'

export interface AuthRequest extends Request {
  user?: { id: string; email: string }
  userId?: string
  role?: string
}
export interface OtpData {
  email: string
  otp: string
}
export interface KycData {
  location: string
  address: string
  officeAddress: string
  dateOfBirth: string
  gender: 'male' | 'female' | 'other'
  selfie: string
  driversLicense: string
  vehicleInformation: string
  vehicleInspectionDocument: string
  availabilityDays: string[]
  categories: string[]
}

export interface ConfirmKycData {
  driverId: string
  kycStatus: 'confirmed' | 'rejected'
}

export interface ResetPasswordData {
  resetToken: string
  newPassword: string
}
export interface Driver {
  id: string
  name: string
  email: string
  phone: string
  status: 'pending' | 'approved' | 'suspended'
  vehicleType: string
  licenseNumber: string
  kycStatus: 'pending' | 'processing' | 'confirmed' | 'rejected'
  kycData?: KycData
}

export interface LoginResponse {
  token: string
  driver: Driver
}

export interface PendingDriver {
  name: string
  email: string
  phone: string
  registrationStatus:
    | 'unconfirmed'
    | 'confirmed'
    | 'kyc_pending'
    | 'kyc_verified'
  createdAt: Date
}

export interface ApiResponse<T = any> {
  statusCode: string
  message?: string
  error?: string
  errors?: string[]
  data?: T
  httpStatus?: number
  resendIn?: number
  email?: string
}
