import { Router } from 'express'
import { body } from 'express-validator'
import {
  register,
  login,
  getProfile,
  updateProfile,
  updateStatus,
  submitKyc,
  getKyc,
  confirmOtp,
  resendOtp,
  getPendingDrivers,
  forgotPassword,
  resetPassword,
  confirmKyc,
} from '../controllers/driver.controller'
import { authenticate } from '../middleware/auth.middleware'
import { validateRequest } from '../middleware/validate.middleware'
import categoryModel from '../models/category.model'

const router = Router()

router.post(
  '/register',
  [
    body('name').notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Invalid email format'),
    body('password')
      .isLength({ min: 6 })
      .withMessage('Password must be at least 6 characters'),
    body('phone').notEmpty().withMessage('Phone number is required'),
  ],
  validateRequest,
  register
)
router.post(
  '/confirm-otp',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('otp')
      .isLength({ min: 4, max: 4 })
      .withMessage('OTP must be 4 digits'),
  ],
  validateRequest,
  confirmOtp
)

router.post(
  '/resend-otp',
  [body('email').isEmail().withMessage('Invalid email format')],
  validateRequest,
  resendOtp
)

router.post(
  '/forgot-password',
  [body('email').isEmail().withMessage('Invalid email format')],
  validateRequest,
  forgotPassword
)

router.post(
  '/reset-password',
  [
    body('resetToken').notEmpty().withMessage('Reset token is required'),
    body('newPassword')
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters')
      .matches(/[A-Z]/)
      .withMessage('Password must contain at least one uppercase letter')
      .matches(/[a-z]/)
      .withMessage('Password must contain at least one lowercase letter')
      .matches(/\d/)
      .withMessage('Password must contain at least one number'),
  ],
  validateRequest,
  resetPassword
)

router.get('/pending', authenticate, getPendingDrivers)

router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  validateRequest,
  login
)

router.get('/profile', authenticate, getProfile)

router.put(
  '/profile',
  authenticate,
  [
    body('name').optional().notEmpty().withMessage('Name cannot be empty'),
    body('phone')
      .optional()
      .notEmpty()
      .withMessage('Phone number cannot be empty'),
    body('vehicleType')
      .optional()
      .notEmpty()
      .withMessage('Vehicle type cannot be empty'),
    body('licenseNumber')
      .optional()
      .notEmpty()
      .withMessage('License number cannot be empty'),
  ],
  validateRequest,
  updateProfile
)

router.put(
  '/status',
  authenticate,
  [
    body('driverId').notEmpty().withMessage('Driver ID is required'),
    body('status')
      .isIn(['pending', 'approved', 'suspended'])
      .withMessage('Invalid status'),
  ],
  validateRequest,
  updateStatus
)
router.put(
  '/kyc/confirm',
  authenticate,
  [
    body('driverId').notEmpty().withMessage('Driver ID is required'),
    body('kycStatus')
      .isIn(['approved', 'rejected'])
      .withMessage('Invalid KYC status'),
  ],
  validateRequest,
  confirmKyc
)

router.post(
  '/kyc',
  authenticate,
  [
    body('location').notEmpty().withMessage('Location is required'),
    body('address').notEmpty().withMessage('Address is required'),
    body('officeAddress').notEmpty().withMessage('Office address is required'),
    body('dateOfBirth')
      .isISO8601()
      .toDate()
      .withMessage('Invalid date of birth format'),
    body('gender')
      .isIn(['male', 'female', 'other'])
      .withMessage('Invalid gender'),
    body('selfie').notEmpty().withMessage('Selfie is required'),
    body('driversLicense').notEmpty().withMessage('Driver license is required'),
    body('vehicleInformation')
      .notEmpty()
      .withMessage('Vehicle information is required'),
    body('vehicleInspectionDocument')
      .notEmpty()
      .withMessage('Vehicle inspection document is required'),
    body('availabilityDays')
      .isArray({ min: 1 })
      .withMessage('At least one availability day is required'),
    body('availabilityDays.*')
      .isIn([
        'Monday',
        'Tuesday',
        'Wednesday',
        'Thursday',
        'Friday',
        'Saturday',
        'Sunday',
      ])
      .withMessage('Invalid availability day'),
    body('categories')
      .isArray({ min: 1 })
      .withMessage('At least one category is required'),
    body('categories.*').custom(async (value) => {
      const category = await categoryModel.findOne({ name: value })
      if (!category) {
        throw new Error(`Category ${value} does not exist`)
      }
      return true
    }),
  ],
  validateRequest,
  submitKyc
)

router.get('/kyc', authenticate, getKyc)

export default router
