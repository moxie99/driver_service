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
import multer from 'multer'
import multerS3 from 'multer-s3'
import AWS from 'aws-sdk'
import Category from '../models/category.model'

const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
})

const upload = multer({
  storage: multerS3({
    s3,
    bucket: process.env.AWS_S3_BUCKET!,
    acl: 'private', // Use private for secure access
    metadata: (
      req: any,
      file: { fieldname: any },
      cb: (arg0: null, arg1: { fieldName: any }) => void
    ) => {
      cb(null, { fieldName: file.fieldname })
    },
    key: (
      req: { user: { id: any } },
      file: { fieldname: any; mimetype: string },
      cb: (arg0: null, arg1: string) => void
    ) => {
      const uniqueSuffix = `${Date.now()}-${Math.round(Math.random() * 1e9)}`
      cb(
        null,
        `kyc/${req.user?.id}/${file.fieldname}-${uniqueSuffix}.${
          file.mimetype.split('/')[1]
        }`
      )
    },
  }),
  fileFilter: (
    req: any,
    file: { mimetype: string },
    cb: (arg0: Error | null, arg1: boolean | undefined) => void
  ) => {
    const allowedTypes = ['image/jpeg', 'image/png']
    if (!allowedTypes.includes(file.mimetype)) {
      cb(new Error('Only JPEG and PNG images are allowed'))
    } else {
      cb(null, true)
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
})
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
  upload.fields([
    { name: 'selfie', maxCount: 1 },
    { name: 'driverLicensePicture', maxCount: 1 },
    { name: 'vehicleInformationPicture', maxCount: 1 },
    { name: 'insurancePicture', maxCount: 1 },
    { name: 'vehicleInspectionDocumentPicture', maxCount: 1 },
  ]),
  [
    body('location').notEmpty().withMessage('Location is required'),
    body('address').notEmpty().withMessage('Address is required'),
    body('officeAddress')
      .optional()
      .notEmpty()
      .withMessage('Office address cannot be empty'),
    body('dateOfBirth')
      .isISO8601()
      .toDate()
      .withMessage('Invalid date of birth format'),
    body('gender')
      .isIn(['male', 'female', 'other'])
      .withMessage('Invalid gender'),
    body('availability').notEmpty().withMessage('Availability is required'),
    body('categories')
      .isArray({ min: 1 })
      .withMessage('At least one category is required'),
    body('categories.*').custom(async (value) => {
      const category = await Category.findOne({ name: value })
      if (!category) {
        throw new Error(`Category ${value} does not exist`)
      }
      return true
    }),
    body('selfie').custom((value, { req }) => {
      if (!req.files || !req.files['selfie']) {
        throw new Error('Selfie is required')
      }
      return true
    }),
    body('driverLicensePicture').custom((value, { req }) => {
      if (!req.files || !req.files['driverLicensePicture']) {
        throw new Error('Driver license picture is required')
      }
      return true
    }),
    body('vehicleInformationPicture').custom((value, { req }) => {
      if (!req.files || !req.files['vehicleInformationPicture']) {
        throw new Error('Vehicle information picture is required')
      }
      return true
    }),
    body('insurancePicture').custom((value, { req }) => {
      if (!req.files || !req.files['insurancePicture']) {
        throw new Error('Insurance picture is required')
      }
      return true
    }),
    body('vehicleInspectionDocumentPicture').custom((value, { req }) => {
      if (!req.files || !req.files['vehicleInspectionDocumentPicture']) {
        throw new Error('Vehicle inspection document picture is required')
      }
      return true
    }),
  ],
  validateRequest,
  submitKyc
)

router.get('/kyc', authenticate, getKyc)

export default router
