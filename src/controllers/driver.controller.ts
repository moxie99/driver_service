import { NextFunction, Response } from 'express'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import Driver, { IDriver } from '../models/driver.model'
import { ApiResponse, AuthRequest, OtpData, ResetPasswordData } from '../types'
import { sendOtpEmail } from '../utils/email'
import Otp from '../models/otp.model'
import PendingDriver from '../models/pendingDriver.model'
const generateOtp = () => {
  return Math.floor(1000 + Math.random() * 9000).toString()
}

const validatePassword = (password: string): string | null => {
  const minLength = 8
  const hasUpperCase = /[A-Z]/.test(password)
  const hasLowerCase = /[a-z]/.test(password)
  const hasNumber = /\d/.test(password)
  if (password.length < minLength) {
    return `Password must be at least ${minLength} characters`
  }
  if (!hasUpperCase) {
    return 'Password must contain at least one uppercase letter'
  }
  if (!hasLowerCase) {
    return 'Password must contain at least one lowercase letter'
  }
  if (!hasNumber) {
    return 'Password must contain at least one number'
  }
  return null
}

// Authentication middleware
export const verifyToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const token = req.header('Authorization')?.replace('Bearer ', '')
  if (!token) {
    return res.status(401).json({
      statusCode: '04',
      error: 'Access denied, no token provided',
    } as ApiResponse)
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as {
      id: string
      email: string
    }
    req.user = decoded
    next()
  } catch (error) {
    return res.status(401).json({
      statusCode: '04',
      error: 'Invalid or expired token',
    } as ApiResponse)
  }
}

export const checkEmail = async (
  email: string
): Promise<{ exists: boolean; isDriver: boolean }> => {
  const driver = await Driver.findOne({ email })
  const pending = await PendingDriver.findOne({ email })
  return {
    exists: !!(driver || pending),
    isDriver: !!driver,
  }
}

export const register = async (req: AuthRequest, res: Response) => {
  try {
    const { name, email, password, phone } = req.body
    const passwordError = validatePassword(password)
    if (passwordError) {
      return res.status(400).json({
        statusCode: '01',
        error: passwordError,
      } as ApiResponse)
    }
    const { exists, isDriver } = await checkEmail(email)
    if (isDriver) {
      return res.status(409).json({
        statusCode: '06',
        error: 'Email already registered',
      } as ApiResponse)
    }
    if (exists) {
      return res.status(409).json({
        statusCode: '02',
        message: 'Email awaiting confirmation, please verify OTP',
        email,
      } as ApiResponse)
    }
    const hashedPassword = await bcrypt.hash(password, 8)
    const otp = generateOtp()
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
    const lastSent = new Date()
    await new PendingDriver({
      name,
      email,
      password: hashedPassword,
      phone,
      registrationStatus: 'unconfirmed',
    }).save()
    await Otp.create({
      email,
      otp,
      expiresAt,
      lastSent,
      isValid: true,
      purpose: 'registration',
    })

    await sendOtpEmail(email, otp, 'Registration')
    res.status(200).json({
      statusCode: '00',
      message: 'OTP sent to email',
      email,
      purpose: 'registration',
    } as ApiResponse)
  } catch (error) {
    res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during OTP generation',
    } as ApiResponse)
  }
}

export const confirmOtp = async (
  req: AuthRequest,
  res: Response
): Promise<Response> => {
  try {
    const { email, otp } = req.body as OtpData
    const otpRecord = await Otp.findOne({ email, otp, isValid: true })
    if (!otpRecord) {
      return res.status(400).json({
        statusCode: '01',
        error: 'Invalid OTP',
      } as ApiResponse)
    }
    if (otpRecord.expiresAt < new Date()) {
      await Otp.updateOne({ _id: otpRecord._id }, { isValid: false })
      return res.status(400).json({
        statusCode: '01',
        error: 'OTP expired, please request a new one',
      } as ApiResponse)
    }
    if (otpRecord.purpose === 'registration') {
      const pendingDriver = await PendingDriver.findOne({ email })
      if (!pendingDriver) {
        return res.status(404).json({
          statusCode: '05',
          error: 'Pending registration not found',
        } as ApiResponse)
      }
      const driver = new Driver({
        name: pendingDriver.name,
        email,
        password: pendingDriver.password,
        phone: pendingDriver.phone,
        vehicleType: '',
        licenseNumber: '',
        status: 'pending',
        kycStatus: '',
      })
      await driver.save()
      const token = jwt.sign(
        { id: driver?._id, email },
        process.env.JWT_SECRET!,
        { expiresIn: '7d' }
      )
      await Otp.deleteOne({ email })
      await PendingDriver.deleteOne({ email })
      return res.status(201).json({
        statusCode: '00',
        message: 'Driver registered successfully',
        data: {
          token,
          driver: {
            id: driver?._id,
            name: driver.name,
            email: driver.email,
            phone: driver.phone,
            status: driver.status,
          },
        },
      } as ApiResponse)
    } else if (otpRecord.purpose === 'password_reset') {
      const driver = await Driver.findOne({ email })
      if (!driver) {
        return res.status(404).json({
          statusCode: '05',
          error: 'Driver not found',
        } as ApiResponse)
      }
      const resetToken = jwt.sign(
        { id: driver._id, email },
        process.env.JWT_SECRET!,
        { expiresIn: '15m' }
      )
      await Otp.deleteOne({ email })
      return res.status(200).json({
        statusCode: '00',
        message: 'OTP verified, proceed to reset password',
        data: { resetToken },
      } as ApiResponse)
    } else {
      return res.status(400).json({
        statusCode: '01',
        error: 'Invalid OTP purpose',
      } as ApiResponse)
    }
  } catch (error) {
    return res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during OTP confirmation',
    } as ApiResponse)
  }
}

export const resendOtp = async (req: AuthRequest, res: Response) => {
  try {
    const { email } = req.body
    const pendingDriver = await PendingDriver.findOne({ email })
    if (!pendingDriver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'No pending registration found for this email',
      } as ApiResponse)
    }
    const otpRecord = await Otp.findOne({ email, isValid: true })
    if (otpRecord && otpRecord.expiresAt >= new Date()) {
      const timeSinceLastSent =
        (new Date().getTime() - otpRecord.lastSent.getTime()) / 1000
      if (timeSinceLastSent < 60) {
        return res.status(429).json({
          statusCode: '03',
          error: 'Please wait before requesting another OTP',
          resendIn: Math.ceil(60 - timeSinceLastSent),
        } as ApiResponse)
      }
    }
    const otp = generateOtp()
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
    const lastSent = new Date()
    await Otp.findOneAndUpdate(
      { email },
      { email, otp, expiresAt, lastSent, isValid: true },
      { upsert: true, new: true }
    )
    await sendOtpEmail(email, otp, 'completeOnboarding')
    res.status(200).json({
      statusCode: '00',
      message: 'New OTP sent to your email',
    } as ApiResponse)
  } catch (error) {
    res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during OTP resend',
    } as ApiResponse)
  }
}

export const forgotPassword = async (req: AuthRequest, res: Response) => {
  try {
    const { email } = req.body
    const { isDriver } = await checkEmail(email)
    if (!isDriver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'No registered driver found for this email',
      } as ApiResponse)
    }
    const otpRecord = await Otp.findOne({ email, isValid: true })
    if (otpRecord && otpRecord.expiresAt >= new Date()) {
      const timeSinceLastSent =
        (new Date().getTime() - otpRecord.lastSent.getTime()) / 1000
      if (timeSinceLastSent < 60) {
        return res.status(429).json({
          statusCode: '03',
          error: 'Please wait before requesting another OTP',
          resendIn: Math.ceil(60 - timeSinceLastSent),
        } as ApiResponse)
      }
    }
    const otp = generateOtp()
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
    const lastSent = new Date()
    await Otp.findOneAndUpdate(
      { email },
      {
        email,
        otp,
        expiresAt,
        lastSent,
        isValid: true,
        purpose: 'password_reset',
      },
      { upsert: true, new: true }
    )
    await sendOtpEmail(email, otp, 'forgotPassword')
    res.status(200).json({
      statusCode: '00',
      message: 'OTP sent to your email for password reset',
      email,
    } as ApiResponse)
  } catch (error) {
    res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during password reset request',
    } as ApiResponse)
  }
}

export const resetPassword = async (req: AuthRequest, res: Response) => {
  try {
    const { resetToken, newPassword } = req.body as ResetPasswordData
    const passwordError = validatePassword(newPassword)
    if (passwordError) {
      return res.status(400).json({
        statusCode: '01',
        error: passwordError,
      } as ApiResponse)
    }
    let decoded
    try {
      decoded = jwt.verify(resetToken, process.env.JWT_SECRET!) as {
        id: string
        email: string
      }
    } catch (error) {
      return res.status(401).json({
        statusCode: '04',
        error: 'Invalid or expired reset token',
      } as ApiResponse)
    }
    const driver = await Driver.findById(decoded.id)
    if (!driver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'Driver not found',
      } as ApiResponse)
    }
    const hashedPassword = await bcrypt.hash(newPassword, 8)
    driver.password = hashedPassword
    await driver.save()
    res.status(200).json({
      statusCode: '00',
      message: 'Password reset successfully',
    } as ApiResponse)
  } catch (error) {
    res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during password reset',
    } as ApiResponse)
  }
}

export const getPendingDrivers = async (req: AuthRequest, res: Response) => {
  try {
    if (req.role !== 'admin') {
      return res.status(403).json({
        statusCode: '04',
        error: 'Only admins can access pending drivers',
      } as ApiResponse)
    }
    const pendingDrivers = await PendingDriver.find({
      registrationStatus: 'unconfirmed',
    }).select('name email phone createdAt')
    res.json({
      statusCode: '00',
      data: pendingDrivers,
    } as ApiResponse)
  } catch (error) {
    res.status(500).json({
      statusCode: '01',
      error: 'Internal server error fetching pending drivers',
    } as ApiResponse)
  }
}

export const login = async (req: AuthRequest, res: Response) => {
  try {
    const { email, password } = req.body
    const { exists, isDriver } = await checkEmail(email)
    const driver = await Driver.findOne({ email })
    if (!exists) {
      return res.status(404).json({
        statusCode: '05',
        error: 'Invalid credentials',
      } as ApiResponse)
    }
    const pendingDriver = await PendingDriver.findOne({ email })
    if (!isDriver && !pendingDriver) {
      return res.status(404).json({
        statusCode: '05',
        error:
          'Invalid credentials. Please click on create new account button below',
      } as ApiResponse)
    }
    if (!isDriver && pendingDriver) {
      const otp = generateOtp()
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000) // 5 minutes
      const lastSent = new Date()
      await Otp.findOneAndUpdate(
        { email },
        { email, otp, expiresAt, lastSent, isValid: true },
        { upsert: true, new: true }
      )
      await sendOtpEmail(email, otp, 'completeOnboarding')
      return res.status(400).json({
        statusCode: '02',
        message: 'New OTP sent to email, please confirm your email',
        email,
      } as ApiResponse)
    }
    if (isDriver) {
      if (!driver) {
        return res.status(404).json({
          statusCode: '05',
          error: 'Invalid credentials',
        } as ApiResponse)
      }
      const isMatch = await bcrypt.compare(password, driver.password)
      if (!isMatch) {
        return res.status(401).json({
          statusCode: '04',
          error:
            'Invalid credentials. Please enter the right password, and try again',
        } as ApiResponse)
      }
      const token = jwt.sign(
        { userId: driver._id, role: 'driver' },
        process.env.JWT_SECRET || 'your_jwt_secret',
        { expiresIn: '1h' }
      )
      return res.json({
        statusCode: '00',
        data: {
          token,
          driver: {
            id: driver._id,
            name: driver.name,
            email: driver.email,
            phone: driver.phone,
            vehicleType: driver.vehicleType,
            licenseNumber: driver.licenseNumber,
            status: driver.status,
            kycStatus: driver.kycStatus,
          },
        },
      } as ApiResponse)
    }
  } catch (error) {
    res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during login',
    } as ApiResponse)
  }
}

export const getProfile = async (
  req: AuthRequest,
  res: Response
): Promise<Response> => {
  try {
    const userId = req.user?.id
    if (!userId) {
      return res.status(401).json({
        statusCode: '04',
        error: 'User ID not found in token',
      } as ApiResponse)
    }
    const driver = await Driver.findById(userId)
    if (!driver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'Driver not found',
      } as ApiResponse)
    }
    return res.status(200).json({
      statusCode: '00',
      data: {
        id: driver._id,
        name: driver.name,
        email: driver.email,
        phone: driver.phone,
        status: driver.status,
        vehicleType: driver.vehicleType,
        licenseNumber: driver.licenseNumber,
        kycStatus: driver.kycStatus,
      },
    } as ApiResponse)
  } catch (error) {
    return res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during profile retrieval',
    } as ApiResponse)
  }
}
export const updateProfile = async (
  req: AuthRequest,
  res: Response
): Promise<Response> => {
  try {
    const userId = req.user?.id
    if (!userId) {
      return res.status(401).json({
        statusCode: '04',
        error: 'User ID not found in token',
      } as ApiResponse)
    }
    const { name, phone, vehicleType, licenseNumber } = req.body
    const driver = await Driver.findById(userId)
    if (!driver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'Driver not found',
      } as ApiResponse)
    }
    driver.name = name || driver.name
    driver.phone = phone || driver.phone
    driver.vehicleType = vehicleType || driver.vehicleType
    driver.licenseNumber = licenseNumber || driver.licenseNumber
    await driver.save()
    return res.status(200).json({
      statusCode: '00',
      message: 'Profile updated successfully',
      data: {
        id: driver._id,
        name: driver.name,
        email: driver.email,
        phone: driver.phone,
        vehicleType: driver.vehicleType,
        licenseNumber: driver.licenseNumber,
        status: driver.status,
        kycStatus: driver.kycStatus,
      },
    } as ApiResponse)
  } catch (error) {
    return res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during profile update',
    } as ApiResponse)
  }
}

export const updateStatus = async (
  req: AuthRequest,
  res: Response
): Promise<Response> => {
  try {
    const { driverId, status } = req.body
    const driver = await Driver.findById(driverId)
    if (!driver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'Driver not found',
      } as ApiResponse)
    }
    driver.status = status
    await driver.save()
    return res.status(200).json({
      statusCode: '00',
      message: 'Driver status updated successfully',
    } as ApiResponse)
  } catch (error) {
    return res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during status update',
    } as ApiResponse)
  }
}

export const submitKyc = async (req: AuthRequest, res: Response) => {
  try {
    const driver = await Driver.findById(req.userId)
    if (!driver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'Driver not found',
      } as ApiResponse)
    }
    if (driver.kycStatus === 'processing' || driver.kycStatus === 'confirmed') {
      return res.status(400).json({
        statusCode: '01',
        error: 'KYC already submitted or approved',
      } as ApiResponse)
    }
    const {
      location,
      address,
      officeAddress,
      dateOfBirth,
      gender,
      selfie,
      driverLicensePicture,
      vehicleInformationPicture,
      vehicleInspectionDocumentPicture,
      daysOfAvailability,
      categories,
    } = req.body
    driver.kycData = {
      location,
      address,
      officeAddress,
      dateOfBirth,
      gender,
      selfie,
      driversLicense: driverLicensePicture,
      vehicleInformation: vehicleInformationPicture,
      vehicleInspectionDocument: vehicleInspectionDocumentPicture,
      availabilityDays: daysOfAvailability,
      categories,
    }
    driver.kycStatus = 'processing'
    await driver.save()
    return res.status(200).json({
      statusCode: '00',
      message: 'KYC submitted successfully, now processing',
      data: { kycStatus: driver.kycStatus, kycData: driver.kycData },
    } as ApiResponse)
  } catch (error) {
    res.status(500).json({
      statusCode: '01',
      error: 'Internal server error submitting KYC',
    } as ApiResponse)
  }
}

export const getKyc = async (
  req: AuthRequest,
  res: Response
): Promise<Response> => {
  try {
    const userId = req.user?.id
    if (!userId) {
      return res.status(401).json({
        statusCode: '04',
        error: 'User ID not found in token',
      } as ApiResponse)
    }
    const driver = await Driver.findById(userId)
    if (!driver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'Driver not found',
      } as ApiResponse)
    }
    return res.status(200).json({
      statusCode: '00',
      data: {
        kycStatus: driver.kycStatus,
        kycData: driver.kycData || {
          location: '',
          address: '',
          officeAddress: '',
          dateOfBirth: '',
          gender: '',
          selfie: '',
          driverLicensePicture: '',
          vehicleInformationPicture: '',
          vehicleInspectionDocumentPicture: '',
          daysOfAvailability: [],
          categories: [],
        },
      },
    } as ApiResponse)
  } catch (error) {
    return res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during KYC retrieval',
    } as ApiResponse)
  }
}

export const confirmKyc = async (
  req: AuthRequest,
  res: Response
): Promise<Response> => {
  try {
    const { driverId, kycStatus } = req.body
    const driver = await Driver.findById(driverId)
    if (!driver) {
      return res.status(404).json({
        statusCode: '05',
        error: 'Driver not found',
      } as ApiResponse)
    }
    if (driver.kycStatus !== 'processing') {
      return res.status(400).json({
        statusCode: '01',
        error: 'KYC is not in processing state',
      } as ApiResponse)
    }
    driver.kycStatus = kycStatus
    await driver.save()
    return res.status(200).json({
      statusCode: '00',
      message: 'KYC status updated successfully',
      data: { kycStatus: driver.kycStatus },
    } as ApiResponse)
  } catch (error) {
    return res.status(500).json({
      statusCode: '01',
      error: 'Internal server error during KYC confirmation',
    } as ApiResponse)
  }
}